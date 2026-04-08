# frozen_string_literal: true
# name: digest-report2
# about: POST to external endpoint after digest email is sent (failsafe, async) + optional open tracking pixel + optional Message-ID domain swap + optional switch to force pixel to use Discourse base_url + debug logs + increments user's digest_sent_counter + optional local PostgreSQL logging
# version: 1.14.0
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "cgi"
  require "time"
  require "openssl"
  require "securerandom"
  require "base64"
  require "json"

  module ::DigestReport
    PLUGIN_NAME = "digest-report2"

    # =========================
    # SETTINGS (SiteSettings)
    # =========================
    def self.enabled?
      return false unless SiteSetting.digest_report2_enabled
      return false if SiteSetting.digest_report2_endpoint_url.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.endpoint_url
      SiteSetting.digest_report2_endpoint_url.to_s.strip
    rescue StandardError
      ""
    end

    def self.open_tracking_enabled?
      !!SiteSetting.digest_report2_open_tracking_enabled
    rescue StandardError
      false
    end

    def self.message_id_swap_enabled?
      !!SiteSetting.digest_report2_message_id_swap_enabled
    rescue StandardError
      false
    end

    # If true, tracking pixel URL ALWAYS uses Discourse.base_url (default Discourse domain),
    # ignoring override/first-link swapping rules.
    # If false, pixel follows the existing "swap/target domain" resolution rules.
    def self.pixel_force_discourse_domain?
      !!SiteSetting.digest_report2_pixel_force_discourse_domain
    rescue StandardError
      false
    end

    # Optional: if set, use this host for BOTH pixel + Message-ID swap target (when not forcing Discourse pixel domain)
    # If blank: derive from first found <a href="http(s)://..."> link.
    def self.target_domain_override
      SiteSetting.digest_report2_target_domain_override.to_s.strip
    rescue StandardError
      ""
    end

    # If true, each sent digest is also inserted into a local PostgreSQL table.
    def self.local_pg_enabled?
      !!SiteSetting.digest_report2_local_pg_enabled
    rescue StandardError
      false
    end

    # =========================
    # HARD-CODED SETTINGS
    # =========================
    DEFAULT_EMAIL_ID = "99999999"

    # ===== ENCRYPTED TOKEN SETTINGS =====
    TOKEN_KEY_HEX = "7c4d2a1f9b8e0c3d4f6a7b8c9d0e1f2233445566778899aabbccddeeff001122"
    TOKEN_PREFIX = "v1"
    TOKEN_MAX_LEN = 2000

    # ===== DEBUG LOGGING =====
    DEBUG_LOG = true

    # ===== LOCAL POSTGRES LOGGING =====
    PG_TABLE_NAME = "digest_report_logs"

    # POST field names
    EMAIL_ID_FIELD              = "email_id"
    OPEN_TRACKING_USED_FIELD    = "open_tracking_used"

    TOPIC_IDS_FIELD             = "topic_ids"
    TOPIC_COUNT_FIELD           = "topic_ids_count"
    FIRST_TOPIC_ID_FIELD        = "first_topic_id"

    SUBJECT_FIELD               = "subject"
    SUBJECT_PRESENT_FLD         = "subject_present"

    FROM_EMAIL_FIELD            = "from_email"

    USER_ID_FIELD               = "user_id"
    USERNAME_FIELD              = "username"
    USER_CREATED_AT_FIELD       = "user_created_at_utc"

    # SMTP router fields to PHP
    SMTP_PROVIDER_ID_FIELD      = "provider_id"
    SMTP_PROVIDER_SLOT_FIELD    = "provider_slot"
    SMTP_PROVIDER_WEIGHT_FIELD  = "provider_weight"
    SMTP_ROUTING_REASON_FIELD   = "routing_reason"
    SMTP_ROUTING_UUID_FIELD     = "routing_uuid"

    # expected headers (set by discourse-multi-smtp-router)
    HDR_PROVIDER_ID     = "X-Multi-SMTP-Router-Provider-Id"
    HDR_PROVIDER_SLOT   = "X-Multi-SMTP-Router-Provider-Slot"
    HDR_PROVIDER_WEIGHT = "X-Multi-SMTP-Router-Provider-Weight"
    HDR_ROUTING_REASON  = "X-Multi-SMTP-Router-Routing-Reason"
    HDR_ROUTING_UUID    = "X-Multi-SMTP-Router-UUID"

    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    JOB_RETRY_COUNT = 2

    # ===== Digest counter custom field =====
    DIGEST_COUNTER_FIELD = "digest_sent_counter"

    STORE_NAMESPACE = PLUGIN_NAME
    def self.store_key_last_email_id(user_id)
      "last_email_id_user_#{user_id}"
    end

    # Module-level flag so ensure_pg_table! only runs DDL once per process lifetime
    @pg_table_ensured = false

    def self.log(msg)
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.log_error(msg)
      Rails.logger.error("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.dlog(msg)
      return unless DEBUG_LOG
      log("DEBUG #{msg}")
    rescue StandardError
    end

    def self.dlog_error(msg)
      return unless DEBUG_LOG
      log_error("DEBUG #{msg}")
    rescue StandardError
    end

    def self.safe_str(v, max_len)
      s = v.to_s.strip
      s = s[0, max_len] if s.length > max_len
      s
    rescue StandardError
      ""
    end

    def self.safe_iso8601(t)
      return "" if t.nil?
      begin
        tt = t.respond_to?(:utc) ? t.utc : t
        tt.iso8601
      rescue StandardError
        ""
      end
    end

    def self.store_last_email_id_for_user(user_id, email_id)
      return if user_id.to_i <= 0
      return if email_id.to_s.strip.empty?
      PluginStore.set(STORE_NAMESPACE, store_key_last_email_id(user_id.to_i), email_id.to_s.strip)
      true
    rescue StandardError
      false
    end

    def self.get_last_email_id_for_user(user_id)
      return "" if user_id.to_i <= 0
      v = PluginStore.get(STORE_NAMESPACE, store_key_last_email_id(user_id.to_i))
      v.to_s.strip
    rescue StandardError
      ""
    end

    def self.header_val(message, key)
      begin
        v = message&.header&.[](key)
        v.to_s.strip
      rescue StandardError
        ""
      end
    end

    def self.set_digest_report_headers!(mail_message, email_id:, open_tracking_used:, user_id:)
      return false if mail_message.nil?
      begin
        mail_message.header["X-Digest-Report-Email-Id"] = email_id.to_s
        mail_message.header["X-Digest-Report-Open-Tracking-Used"] = open_tracking_used.to_s
        mail_message.header["X-Digest-Report-User-Id"] = user_id.to_s
        true
      rescue StandardError
        false
      end
    end

    # =========================
    # DIGEST COUNTER INCREMENT
    # =========================
    def self.increment_digest_counter_for_user(user)
      return false if user.nil?
      field = DIGEST_COUNTER_FIELD.to_s.strip
      return false if field.empty?

      User.transaction do
        u = User.lock.find(user.id)
        u.custom_fields ||= {}

        cur_raw = u.custom_fields[field]
        cur = cur_raw.to_i
        cur = 0 if cur < 0

        u.custom_fields[field] = (cur + 1).to_s
        u.save_custom_fields(true)
      end

      true
    rescue StandardError => e
      dlog_error("increment_digest_counter_for_user failed user_id=#{user&.id} err=#{e.class}: #{e.message}")
      false
    end

    def self.extract_email_body(message)
      return "" if message.nil?

      if message.respond_to?(:multipart?) && message.multipart?
        html = ""
        txt  = ""
        begin
          html = message.html_part&.body&.decoded.to_s
        rescue StandardError
          html = ""
        end
        begin
          txt = message.text_part&.body&.decoded.to_s
        rescue StandardError
          txt = ""
        end
        return html unless html.to_s.empty?
        return txt unless txt.to_s.empty?
      end

      begin
        message.body&.decoded.to_s
      rescue StandardError
        ""
      end
    end

    def self.first_recipient_email(message)
      begin
        raw = Array(message&.to).first.to_s.strip
        return "" if raw.empty?
        begin
          addr = Mail::Address.new(raw)
          return addr.address.to_s.strip
        rescue StandardError
          m = raw.match(/([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})/i)
          return m ? m[1].to_s.strip : raw
        end
      rescue StandardError
        ""
      end
    end

    # Extract candidate URLs from raw body (fallback for plain text)
    def self.extract_urls_from_body(body)
      return [] if body.to_s.empty?
      begin
        b = CGI.unescapeHTML(body.to_s) rescue body.to_s
        b.scan(%r{https?://[^\s"'<>()]+}i)
      rescue StandardError
        []
      end
    end

    # Return the first <a ... href="http(s)://..."> (or single-quoted) from HTML
    # No Nokogiri: regex-based.
    def self.first_href_link_from_html(html)
      return "" if html.to_s.empty?

      s = html.to_s

      m = s.match(/<a\b[^>]*\bhref\s*=\s*"((?:https?:\/\/)[^"]+)"/i)
      return m[1].to_s.strip if m && m[1]

      m = s.match(/<a\b[^>]*\bhref\s*=\s*'((?:https?:\/\/)[^']+)'/i)
      return m[1].to_s.strip if m && m[1]

      ""
    rescue StandardError
      ""
    end

    def self.first_link_url_from_message(message)
      body = extract_email_body(message)
      return "" if body.to_s.empty?

      if body.include?("<a") || body.include?("<html") || body.include?("<body")
        href = first_href_link_from_html(body)
        return href unless href.to_s.empty?
      end

      urls = extract_urls_from_body(body)
      urls.each do |raw|
        next if raw.to_s.empty?
        u = raw.to_s.gsub(/[)\].,;]+$/, "")
        uri = (URI.parse(u) rescue nil)
        next if uri.nil?
        next if uri.scheme.to_s.empty? || uri.host.to_s.empty?
        return u
      end

      ""
    rescue StandardError
      ""
    end

    def self.first_link_host_from_message(message)
      u = first_link_url_from_message(message)
      return "" if u.to_s.strip.empty?
      uri = (URI.parse(u) rescue nil)
      return "" if uri.nil?
      uri.host.to_s.strip
    rescue StandardError
      ""
    end

    def self.first_link_base_url_from_message(message)
      u = first_link_url_from_message(message)
      return "" if u.to_s.strip.empty?

      uri = (URI.parse(u) rescue nil)
      return "" if uri.nil?
      return "" if uri.scheme.to_s.empty? || uri.host.to_s.empty?

      scheme = uri.scheme.to_s.downcase
      host = uri.host.to_s

      port = uri.port.to_i
      default_port = (scheme == "https" ? 443 : 80)
      port_part = (port > 0 && port != default_port) ? ":#{port}" : ""

      "#{scheme}://#{host}#{port_part}"
    rescue StandardError
      ""
    end

    # Discourse hostname (origin) for swapping
    def self.discourse_origin_host
      uri = (URI.parse(Discourse.base_url.to_s) rescue nil)
      uri&.host.to_s.strip
    rescue StandardError
      ""
    end

    # Target host:
    #  - if override present -> that host
    #  - else first <a href> host (or fallback url host)
    def self.resolve_target_host(mail_message)
      ovr = target_domain_override.to_s.strip
      if !ovr.empty?
        begin
          s = ovr
          s = "https://#{s}" unless s =~ %r{\Ahttps?://}i
          uri = (URI.parse(s) rescue nil)
          h = uri&.host.to_s.strip
          return h if !h.empty?
        rescue StandardError
        end
      end

      first_link_host_from_message(mail_message)
    rescue StandardError
      ""
    end

    # Pixel base URL:
    # - if pixel_force_discourse_domain? -> ALWAYS Discourse.base_url
    # - else:
    #   - if override present -> use https://override (or scheme if provided)
    #   - else use scheme+host(+port) from the first found link
    #   - else fallback to Discourse.base_url
    def self.resolve_pixel_base_url(mail_message)
      return Discourse.base_url.to_s if pixel_force_discourse_domain?

      ovr = target_domain_override.to_s.strip
      if !ovr.empty?
        begin
          s = ovr
          s = "https://#{s}" unless s =~ %r{\Ahttps?://}i
          uri = (URI.parse(s) rescue nil)
          if uri && uri.scheme.to_s != "" && uri.host.to_s != ""
            scheme = uri.scheme.to_s.downcase
            host = uri.host.to_s
            port = uri.port.to_i
            default_port = (scheme == "https" ? 443 : 80)
            port_part = (port > 0 && port != default_port) ? ":#{port}" : ""
            return "#{scheme}://#{host}#{port_part}"
          end
        rescue StandardError
        end
      end

      from_link = first_link_base_url_from_message(mail_message)
      return from_link unless from_link.empty?

      Discourse.base_url.to_s
    rescue StandardError
      Discourse.base_url.to_s
    end

    # Swap Message-ID domain from discourse hostname -> target host
    def self.swap_message_id_domain_from_discourse!(mail_message, target_host)
      return false if mail_message.nil?
      host = target_host.to_s.strip
      return false if host.empty?

      origin = discourse_origin_host
      return false if origin.to_s.strip.empty?

      raw = header_val(mail_message, "Message-ID")
      return false if raw.empty?

      s = raw.strip
      s = s[1..-2].to_s.strip if s.start_with?("<") && s.end_with?(">")
      return false unless s.include?("@")

      local, dom = s.split("@", 2)
      local = local.to_s.strip
      dom   = dom.to_s.strip
      return false if local.empty? || dom.empty?

      # Only swap if current domain matches discourse hostname
      if dom.downcase != origin.downcase
        dlog("Message-ID swap: current=#{dom} origin(discord)=#{origin} -> skip")
        return false
      end

      return true if dom.downcase == host.downcase

      new_mid = "<#{local}@#{host}>"
      mail_message.header["Message-ID"] = new_mid
      dlog("Message-ID swapped: #{raw} -> #{new_mid}")
      true
    rescue StandardError => e
      dlog_error("swap_message_id_domain_from_discourse failed err=#{e.class}: #{e.message}")
      false
    end

    def self.extract_topic_ids_from_message(message)
      body = extract_email_body(message)
      return [] if body.to_s.empty?

      urls = extract_urls_from_body(body)

      ids = []
      seen = {}

      urls.each do |raw|
        next if raw.to_s.empty?
        u = raw.to_s.gsub(/[)\].,;]+$/, "")

        uri = (URI.parse(u) rescue nil)
        next if uri.nil?

        path = uri.path.to_s
        next if path.empty?

        m = path.match(%r{/t/(?:[^/]+/)?(\d+)(?:/|$)}i)
        next if m.nil?

        tid = m[1].to_i
        next if tid <= 0
        next if seen[tid]

        seen[tid] = true
        ids << tid
      end

      ids
    rescue StandardError => e
      ::DigestReport.log_error("extract_topic_ids_from_message error err=#{e.class}: #{e.message}")
      []
    end

    def self.extract_email_id_from_message(message)
      body = extract_email_body(message)
      return "" if body.to_s.empty?

      urls = extract_urls_from_body(body)

      urls.each do |raw|
        next if raw.to_s.empty?
        u = raw.to_s.gsub(/[)\].,;]+$/, "")
        next unless u.include?("email_id=")

        begin
          uri = URI.parse(u)
          q = uri.query.to_s
          if q.to_s.empty? && uri.fragment.to_s.include?("email_id=")
            q = uri.fragment.to_s
          end
          unless q.to_s.empty?
            params = CGI.parse(q)
            v = Array(params["email_id"]).first.to_s
            digits = (v.scan(/\d+/).join rescue "")
            return digits unless digits.empty?
          end
        rescue StandardError
        end

        begin
          m = u.match(/(?:\?|&|#)email_id=([^&#]+)/i)
          if m
            v = m[1].to_s
            digits = (v.scan(/\d+/).join rescue "")
            return digits unless digits.empty?
          end
        rescue StandardError
        end
      end

      ""
    rescue StandardError => e
      ::DigestReport.log_error("extract_email_id_from_message error err=#{e.class}: #{e.message}")
      ""
    end

    # -------------------------
    # TOKEN HELPERS (AES-256-GCM)
    # -------------------------
    def self.b64url_encode(bin)
      Base64.urlsafe_encode64(bin, padding: false)
    end

    def self.build_open_token(email_id:, user_id:, user_email:)
      key_hex = TOKEN_KEY_HEX.to_s.strip
      return "" if key_hex.empty?

      key = [key_hex].pack("H*")
      return "" unless key.bytesize == 32

      payload = {
        "e" => email_id.to_s,
        "u" => user_id.to_s,
        "m" => user_email.to_s,
        "v" => 1
      }

      plain = JSON.generate(payload)

      iv = SecureRandom.random_bytes(12)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_data = ""

      ct  = cipher.update(plain) + cipher.final
      tag = cipher.auth_tag

      TOKEN_PREFIX + "." + b64url_encode(iv + tag + ct)
    rescue StandardError
      ""
    end

    def self.build_tracking_pixel_html(mail_message, email_id:, user_id:, user_email:)
      return "" if email_id.to_s.strip.empty?

      t = build_open_token(email_id: email_id, user_id: user_id, user_email: user_email)
      return "" if t.to_s.empty?

      t = t.to_s[0, TOKEN_MAX_LEN]

      base = resolve_pixel_base_url(mail_message).to_s.strip
      return "" if base.empty?

      pixel_base = "#{base}/digest/open"

      url =
        begin
          uri = URI.parse(pixel_base)
          existing = uri.query.to_s
          add = URI.encode_www_form({ "t" => t })
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{pixel_base}?#{URI.encode_www_form({ "t" => t })}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end

    def self.message_already_has_pixel?(mail_message)
      b = extract_email_body(mail_message)
      return false if b.to_s.empty?
      b.include?("/digest/open?t=") || b.include?("digest/open?t=") || b.include?("/digest/open.gif") || b.include?("digest/open.gif")
    rescue StandardError
      false
    end

    def self.inject_pixel_into_mail!(mail_message, email_id:, user_id:, user_email:)
      return false if mail_message.nil?

      pixel = build_tracking_pixel_html(mail_message, email_id: email_id, user_id: user_id, user_email: user_email)
      if pixel.to_s.empty?
        dlog("inject: pixel html empty -> fail")
        return false
      end

      begin
        if mail_message.respond_to?(:multipart?) && mail_message.multipart?
          hp = mail_message.html_part rescue nil
          return false if hp.nil?

          html = (hp.body.decoded.to_s rescue "")
          return false if html.to_s.empty?

          new_html =
            if html.include?("</body>")
              html.sub("</body>", "#{pixel}</body>")
            else
              html + pixel
            end

          hp.body = new_html rescue nil
          dlog("inject: OK via html_part")
          return true
        end
      rescue StandardError => e
        dlog_error("inject: multipart path error err=#{e.class}: #{e.message}")
      end

      begin
        ct = (mail_message.content_type.to_s rescue "")
        return false unless ct.downcase.include?("text/html")

        html = (mail_message.body.decoded.to_s rescue "")
        return false if html.to_s.empty?

        new_html =
          if html.include?("</body>")
            html.sub("</body>", "#{pixel}</body>")
          else
            html + pixel
          end

        mail_message.body = new_html rescue nil
        dlog("inject: OK via body")
        return true
      rescue StandardError => e
        dlog_error("inject: non-multipart path error err=#{e.class}: #{e.message}")
      end

      false
    rescue StandardError => e
      dlog_error("inject: crash err=#{e.class}: #{e.message}")
      false
    end

    def self.read_router_headers(message)
      {
        provider_id:     header_val(message, HDR_PROVIDER_ID),
        provider_slot:   header_val(message, HDR_PROVIDER_SLOT),
        provider_weight: header_val(message, HDR_PROVIDER_WEIGHT),
        routing_reason:  header_val(message, HDR_ROUTING_REASON),
        routing_uuid:    header_val(message, HDR_ROUTING_UUID)
      }
    rescue StandardError
      { provider_id: "", provider_slot: "", provider_weight: "", routing_reason: "", routing_uuid: "" }
    end

    # =========================
    # LOCAL POSTGRES LOGGING
    # =========================

    # Mirror the PHP endpoint's is_campaign_email_id() logic:
    #   - must start with "0000"
    #   - must have another "000" at index 7 or later
    def self.campaign_email_id?(email_id)
      s = email_id.to_s
      return false unless s.start_with?("0000")
      !s.index("000", 7).nil?
    rescue StandardError
      false
    end

    # Mirror the PHP endpoint's extract_campaignid_from_email_id() logic:
    #   campaignid = s[4 .. (pos_of_second_000 - 1)]
    def self.extract_campaignid(email_id)
      s = email_id.to_s
      return "" unless s.start_with?("0000")
      pos = s.index("000", 7)
      return "" if pos.nil?
      len = pos - 4
      return "" if len <= 0
      cid = s[4, len]
      cid.length > 64 ? cid[0, 64] : cid
    rescue StandardError
      ""
    end

    # email_id must be exactly 20 digits (same rule as PHP validation).
    # The DEFAULT_EMAIL_ID (8 digits) intentionally fails this check
    # so stubs are never written to the table.
    def self.email_id_loggable?(email_id)
      !!(email_id.to_s =~ /\A\d{20}\z/)
    rescue StandardError
      false
    end

    # Parse an ISO-8601 / HTTP-date string to a UTC Time, or nil on failure.
    def self.parse_utc_datetime(str)
      return nil if str.to_s.strip.empty?
      Time.parse(str.to_s.strip).utc
    rescue StandardError
      nil
    end

    # Creates (or verifies) the digest_report_logs table and grants the
    # discourse DB role full privileges. Schema matches the PHP MySQL table.
    # Called once per process lifetime via @pg_table_ensured guard.
    def self.ensure_pg_table!
      return if @pg_table_ensured
      conn = ActiveRecord::Base.connection
      conn.execute(<<~SQL)
        CREATE TABLE IF NOT EXISTS #{PG_TABLE_NAME} (
          id                   BIGSERIAL PRIMARY KEY,
          email_id             VARCHAR(20)  NOT NULL,
          open_tracking_used   SMALLINT     NOT NULL DEFAULT 0,
          isopened             SMALLINT     NOT NULL DEFAULT 0,
          isclicked            SMALLINT     NOT NULL DEFAULT 0,
          iscampaign           SMALLINT     NOT NULL DEFAULT 0,
          campaignid           VARCHAR(64),
          user_email           VARCHAR(255),
          from_email           VARCHAR(255),
          user_id              VARCHAR(32),
          username             VARCHAR(255),
          user_created_at_utc  VARCHAR(40),
          user_created_at_dt   TIMESTAMP WITHOUT TIME ZONE,
          subject              VARCHAR(512),
          subject_present      SMALLINT     NOT NULL DEFAULT 0,
          topic_ids            TEXT,
          topic_ids_count      INTEGER      NOT NULL DEFAULT 0,
          first_topic_id       BIGINT,
          provider_id          VARCHAR(128),
          provider_slot        VARCHAR(128),
          provider_weight      VARCHAR(128),
          routing_reason       TEXT,
          routing_uuid         VARCHAR(200),
          recv_useragent       VARCHAR(512),
          recv_user_ip         VARCHAR(64),
          created_at           TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
          CONSTRAINT uq_#{PG_TABLE_NAME}_email_id UNIQUE (email_id)
        )
      SQL
      [
        "CREATE INDEX IF NOT EXISTS idx_drl_user_email          ON #{PG_TABLE_NAME} (user_email)",
        "CREATE INDEX IF NOT EXISTS idx_drl_user_id             ON #{PG_TABLE_NAME} (user_id)",
        "CREATE INDEX IF NOT EXISTS idx_drl_first_topic_id      ON #{PG_TABLE_NAME} (first_topic_id)",
        "CREATE INDEX IF NOT EXISTS idx_drl_open_tracking_used  ON #{PG_TABLE_NAME} (open_tracking_used)",
        "CREATE INDEX IF NOT EXISTS idx_drl_isopened            ON #{PG_TABLE_NAME} (isopened)",
        "CREATE INDEX IF NOT EXISTS idx_drl_isclicked           ON #{PG_TABLE_NAME} (isclicked)",
        "CREATE INDEX IF NOT EXISTS idx_drl_iscampaign          ON #{PG_TABLE_NAME} (iscampaign)",
        "CREATE INDEX IF NOT EXISTS idx_drl_campaignid          ON #{PG_TABLE_NAME} (campaignid)",
        "CREATE INDEX IF NOT EXISTS idx_drl_provider_id         ON #{PG_TABLE_NAME} (provider_id)",
      ].each { |sql| conn.execute(sql) }
      conn.execute("GRANT ALL PRIVILEGES ON TABLE #{PG_TABLE_NAME} TO discourse")
      conn.execute("GRANT USAGE, SELECT ON SEQUENCE #{PG_TABLE_NAME}_id_seq TO discourse")
      @pg_table_ensured = true
      dlog("ensure_pg_table!: table ready")
    rescue StandardError => e
      log_error("ensure_pg_table! failed err=#{e.class}: #{e.message}")
    end

    def self.insert_pg_log(
      email_id:, open_tracking_used:, user_email:, from_email:,
      user_id:, username:, user_created_at_utc:, user_created_at_dt:,
      subject:, subject_present:,
      topic_ids_csv:, topic_ids_count:, first_topic_id:,
      provider_id:, provider_slot:, provider_weight:,
      routing_reason:, routing_uuid:,
      iscampaign:, campaignid:
    )
      conn = ActiveRecord::Base.connection
      q    = ->(v) { conn.quote(v) }

      uid_val  = user_id.to_s.strip.empty?     ? "NULL" : q.call(user_id.to_s.strip)
      fid_val  = first_topic_id.to_s.strip.empty? ? "NULL" : q.call(first_topic_id.to_s.strip.to_i)
      uat_val  = user_created_at_dt.nil?        ? "NULL" : q.call(user_created_at_dt.strftime("%Y-%m-%d %H:%M:%S"))
      cid_val  = campaignid.to_s.empty?         ? "NULL" : q.call(campaignid.to_s)
      ot_val   = open_tracking_used.to_s == "1" ? 1 : 0
      sp_val   = subject_present.to_s == "1"    ? 1 : 0

      conn.execute(<<~SQL)
        INSERT INTO #{PG_TABLE_NAME} (
          email_id, open_tracking_used, isopened, isclicked,
          iscampaign, campaignid,
          user_email, from_email, user_id, username,
          user_created_at_utc, user_created_at_dt,
          subject, subject_present,
          topic_ids, topic_ids_count, first_topic_id,
          provider_id, provider_slot, provider_weight,
          routing_reason, routing_uuid,
          recv_useragent, recv_user_ip
        ) VALUES (
          #{q.call(email_id.to_s)}, #{q.call(ot_val)}, 0, 0,
          #{q.call(iscampaign ? 1 : 0)}, #{cid_val},
          #{q.call(user_email.to_s)}, #{q.call(from_email.to_s)}, #{uid_val}, #{q.call(username.to_s)},
          #{q.call(user_created_at_utc.to_s)}, #{uat_val},
          #{q.call(subject.to_s)}, #{q.call(sp_val)},
          #{q.call(topic_ids_csv.to_s)}, #{q.call(topic_ids_count.to_i)}, #{fid_val},
          #{q.call(provider_id.to_s)}, #{q.call(provider_slot.to_s)}, #{q.call(provider_weight.to_s)},
          #{q.call(routing_reason.to_s)}, #{q.call(routing_uuid.to_s)},
          #{q.call("Discourse/#{Discourse::VERSION::STRING rescue "?"} #{PLUGIN_NAME}")}, NULL
        )
        ON CONFLICT (email_id) DO NOTHING
      SQL
      dlog("insert_pg_log: OK email_id=#{email_id} iscampaign=#{iscampaign ? 1 : 0} campaignid=#{campaignid}")
    rescue StandardError => e
      log_error("insert_pg_log failed err=#{e.class}: #{e.message}")
    end
  end

  # BEFORE send: extract email_id + inject pixel (optional) + stamp headers + Message-ID swap (optional)
  DiscourseEvent.on(:before_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled? || ::DigestReport.local_pg_enabled?
      next unless email_type.to_s == "digest"

      existing_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      next unless existing_id.empty?

      recipient = ::DigestReport.first_recipient_email(message)

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end
      uid = user ? user.id : 0

      email_id = ::DigestReport.extract_email_id_from_message(message)
      email_id = ::DigestReport.get_last_email_id_for_user(uid) if email_id.to_s.strip.empty? && uid > 0
      if email_id.to_s.strip.empty?
        email_id = ::DigestReport::DEFAULT_EMAIL_ID
        ::DigestReport.dlog("before_email_send: email_id missing -> DEFAULT=#{email_id}")
      end

      # Message-ID swap: ALWAYS from Discourse hostname -> (override OR first href host)
      if ::DigestReport.message_id_swap_enabled?
        target_host = ::DigestReport.resolve_target_host(message)
        if target_host.to_s.strip.empty?
          ::DigestReport.dlog("Message-ID swap: no target host resolved -> skip")
        else
          ::DigestReport.swap_message_id_domain_from_discourse!(message, target_host)
        end
      end

      injected = false
      if ::DigestReport.open_tracking_enabled?
        if ::DigestReport.message_already_has_pixel?(message)
          injected = true
        else
          injected = ::DigestReport.inject_pixel_into_mail!(
            message,
            email_id: email_id,
            user_id: uid,
            user_email: recipient
          )
        end
      end

      open_used = injected ? "1" : "0"

      ::DigestReport.set_digest_report_headers!(
        message,
        email_id: email_id.to_s,
        open_tracking_used: open_used,
        user_id: uid
      )

      ::DigestReport.dlog(
        "before_email_send: uid=#{uid} email=#{recipient} email_id=#{email_id} " \
        "pixel=#{open_used} mid_swap=#{::DigestReport.message_id_swap_enabled? ? '1' : '0'} " \
        "pixel_force_discourse=#{::DigestReport.pixel_force_discourse_domain? ? '1' : '0'}"
      )

      if uid > 0 && !email_id.to_s.strip.empty? && email_id.to_s != ::DigestReport::DEFAULT_EMAIL_ID
        ::DigestReport.store_last_email_id_for_user(uid, email_id)
      end
    rescue StandardError => e
      ::DigestReport.dlog_error("before_email_send error err=#{e.class}: #{e.message}")
    end
  end

  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        do_http = ::DigestReport.enabled?
        do_pg   = ::DigestReport.local_pg_enabled?
        return unless do_http || do_pg

        email_id = args[:email_id].to_s.strip
        email_id = ::DigestReport::DEFAULT_EMAIL_ID if email_id.empty?

        open_tracking_used = args[:open_tracking_used].to_s.strip
        open_tracking_used = "0" unless open_tracking_used == "1"

        user_email = args[:user_email].to_s.strip
        subject = ::DigestReport.safe_str(args[:subject], ::DigestReport::SUBJECT_MAX_LEN)
        subject_present = subject.empty? ? "0" : "1"
        from_email = ::DigestReport.safe_str(args[:from_email], ::DigestReport::FROM_MAX_LEN)

        user_id  = args[:user_id].to_s
        username = ::DigestReport.safe_str(args[:username], ::DigestReport::USERNAME_MAX_LEN)
        user_created_at_utc = args[:user_created_at_utc].to_s

        incoming_ids = Array(args[:topic_ids]).map { |x| x.to_i }
        seen = {}
        topic_ids_ordered = []
        incoming_ids.each do |tid|
          next if tid <= 0
          next if seen[tid]
          seen[tid] = true
          topic_ids_ordered << tid
        end

        topic_ids_csv   = topic_ids_ordered.join(",")
        topic_ids_count = topic_ids_ordered.length
        first_topic_id  = topic_ids_ordered[0] ? topic_ids_ordered[0].to_s : ""

        provider_id     = args[:provider_id].to_s.strip
        provider_slot   = args[:provider_slot].to_s.strip
        provider_weight = args[:provider_weight].to_s.strip
        routing_reason  = args[:routing_reason].to_s.strip
        routing_uuid    = args[:routing_uuid].to_s.strip

        # ---- HTTP POST to remote PHP endpoint ----
        if do_http
          url = ::DigestReport.endpoint_url
          uri = (URI.parse(url) rescue nil)
          unless uri.nil?
            form_kv = [
              [::DigestReport::EMAIL_ID_FIELD, email_id],
              [::DigestReport::OPEN_TRACKING_USED_FIELD, open_tracking_used],
              ["user_email", user_email],

              [::DigestReport::FROM_EMAIL_FIELD, from_email],

              [::DigestReport::USER_ID_FIELD, user_id],
              [::DigestReport::USERNAME_FIELD, username],
              [::DigestReport::USER_CREATED_AT_FIELD, user_created_at_utc],

              [::DigestReport::SUBJECT_FIELD, subject],
              [::DigestReport::SUBJECT_PRESENT_FLD, subject_present],

              [::DigestReport::TOPIC_IDS_FIELD, topic_ids_csv],
              [::DigestReport::TOPIC_COUNT_FIELD, topic_ids_count.to_s],
              [::DigestReport::FIRST_TOPIC_ID_FIELD, first_topic_id],

              [::DigestReport::SMTP_PROVIDER_ID_FIELD, provider_id],
              [::DigestReport::SMTP_PROVIDER_SLOT_FIELD, provider_slot],
              [::DigestReport::SMTP_PROVIDER_WEIGHT_FIELD, provider_weight],
              [::DigestReport::SMTP_ROUTING_REASON_FIELD, routing_reason],
              [::DigestReport::SMTP_ROUTING_UUID_FIELD, routing_uuid]
            ]

            body = URI.encode_www_form(form_kv)

            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = (uri.scheme == "https")
            http.open_timeout = ::DigestReport::OPEN_TIMEOUT_SECONDS
            http.read_timeout = ::DigestReport::READ_TIMEOUT_SECONDS
            http.write_timeout = ::DigestReport::WRITE_TIMEOUT_SECONDS if http.respond_to?(:write_timeout=)

            req = Net::HTTP::Post.new(uri.request_uri)
            req["Content-Type"] = "application/x-www-form-urlencoded"
            req["User-Agent"] = "Discourse/#{Discourse::VERSION::STRING} #{::DigestReport::PLUGIN_NAME}"
            req.body = body

            http.start { |h| h.request(req) } rescue nil
          end
        end

        # ---- Insert into local PostgreSQL table ----
        if do_pg
          # Skip stubs (DEFAULT_EMAIL_ID is 8 digits; valid ids are exactly 20 digits)
          if ::DigestReport.email_id_loggable?(email_id)
            iscampaign     = ::DigestReport.campaign_email_id?(email_id)
            campaignid     = iscampaign ? ::DigestReport.extract_campaignid(email_id) : ""
            user_created_at_dt = ::DigestReport.parse_utc_datetime(user_created_at_utc)

            ::DigestReport.ensure_pg_table!
            ::DigestReport.insert_pg_log(
              email_id:            email_id,
              open_tracking_used:  open_tracking_used,
              user_email:          user_email,
              from_email:          from_email,
              user_id:             user_id,
              username:            username,
              user_created_at_utc: user_created_at_utc,
              user_created_at_dt:  user_created_at_dt,
              subject:             subject,
              subject_present:     subject_present,
              topic_ids_csv:       topic_ids_csv,
              topic_ids_count:     topic_ids_count,
              first_topic_id:      first_topic_id,
              provider_id:         provider_id,
              provider_slot:       provider_slot,
              provider_weight:     provider_weight,
              routing_reason:      routing_reason,
              routing_uuid:        routing_uuid,
              iscampaign:          iscampaign,
              campaignid:          campaignid
            )
          else
            ::DigestReport.dlog("insert_pg_log: skip email_id=#{email_id} (not 20 digits)")
          end
        end

      rescue StandardError => e
        ::DigestReport.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled? || ::DigestReport.local_pg_enabled?
      next unless email_type.to_s == "digest"

      recipient = ::DigestReport.first_recipient_email(message)

      subject = ::DigestReport.safe_str(message&.subject, ::DigestReport::SUBJECT_MAX_LEN) rescue ""
      from_email = Array(message&.from).first.to_s.strip rescue ""

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end

      ::DigestReport.increment_digest_counter_for_user(user) if user

      uid = user ? user.id : 0
      user_id = user ? user.id : ""
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)

      email_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      if email_id.to_s.strip.empty?
        email_id = ::DigestReport.extract_email_id_from_message(message)
        email_id = ::DigestReport.get_last_email_id_for_user(uid) if email_id.to_s.strip.empty? && uid > 0
      end
      email_id = ::DigestReport::DEFAULT_EMAIL_ID if email_id.to_s.strip.empty?

      open_tracking_used = ::DigestReport.header_val(message, "X-Digest-Report-Open-Tracking-Used")
      open_tracking_used = (open_tracking_used == "1" ? "1" : "0")

      router = ::DigestReport.read_router_headers(message)

      Jobs.enqueue(
        :digest_report_postback,
        email_id: email_id.to_s,
        open_tracking_used: open_tracking_used,
        user_email: recipient,
        from_email: from_email,
        user_id: user_id,
        username: username,
        user_created_at_utc: user_created_at_utc,
        subject: subject,
        topic_ids: topic_ids,
        provider_id: router[:provider_id],
        provider_slot: router[:provider_slot],
        provider_weight: router[:provider_weight],
        routing_reason: router[:routing_reason],
        routing_uuid: router[:routing_uuid]
      )
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
