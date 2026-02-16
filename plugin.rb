# frozen_string_literal: true

# name: digest-report2
# about: POST to external endpoint after digest email is sent (failsafe, async) + optional open tracking pixel + debug logs + increments user's digest_sent_counter
# version: 1.8.0
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
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL = "http://172.17.0.1:8081/digest_report.php"

    # ===== Open tracking switch =====
    OPEN_TRACKING_ENABLED = true

    # Pixel endpoint (NO-extension)
    OPEN_TRACKING_PIXEL_BASE_URL = "#{Discourse.base_url}/digest/open"

    # If we can't find an email_id in any link, use this
    DEFAULT_EMAIL_ID = "99999999"

    # ===== ENCRYPTED TOKEN SETTINGS =====
    TOKEN_KEY_HEX = "7c4d2a1f9b8e0c3d4f6a7b8c9d0e1f2233445566778899aabbccddeeff001122"
    TOKEN_PREFIX = "v1"
    TOKEN_MAX_LEN = 2000

    # ===== DEBUG LOGGING =====
    DEBUG_LOG = true

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

    # NEW: SMTP router fields to PHP
    SMTP_PROVIDER_ID_FIELD      = "provider_id"
    SMTP_PROVIDER_SLOT_FIELD    = "provider_slot"
    SMTP_PROVIDER_WEIGHT_FIELD  = "provider_weight"
    SMTP_ROUTING_REASON_FIELD   = "routing_reason"
    SMTP_ROUTING_UUID_FIELD     = "routing_uuid"

    # NEW: expected headers (set by discourse-multi-smtp-router)
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
    # =========================

    STORE_NAMESPACE = PLUGIN_NAME
    def self.store_key_last_email_id(user_id)
      "last_email_id_user_#{user_id}"
    end

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

    def self.enabled?
      return false unless ENABLED
      return false if ENDPOINT_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.open_tracking_enabled?
      return false unless OPEN_TRACKING_ENABLED
      return false if OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
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

        # Ensure custom_fields are loaded
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

    def self.extract_topic_ids_from_message(message)
      body = extract_email_body(message)
      return [] if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      urls =
        begin
          body.scan(%r{https?://[^\s"'<>()]+}i)
        rescue StandardError
          []
        end

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

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      urls =
        begin
          body.scan(%r{https?://[^\s"'<>()]+}i)
        rescue StandardError
          []
        end

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

    def self.build_tracking_pixel_html(email_id:, user_id:, user_email:)
      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      return "" if base.empty?
      return "" if email_id.to_s.strip.empty?

      t = build_open_token(email_id: email_id, user_id: user_id, user_email: user_email)
      return "" if t.to_s.empty?

      t = t.to_s[0, TOKEN_MAX_LEN]

      url =
        begin
          uri = URI.parse(base)
          existing = uri.query.to_s
          add = URI.encode_www_form({ "t" => t })
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{base}?#{URI.encode_www_form({ "t" => t })}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end

    def self.message_already_has_pixel?(mail_message)
      b = extract_email_body(mail_message)
      return false if b.to_s.empty?

      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      legacy = base.end_with?("/digest/open") ? (base + ".gif") : "#{Discourse.base_url}/digest/open.gif"

      b.include?(base) || b.include?(legacy) || b.include?("digest/open?t=")
    rescue StandardError
      false
    end

    def self.inject_pixel_into_mail!(mail_message, email_id:, user_id:, user_email:)
      r
