# frozen_string_literal: true

# name: digest-report2
# about: POST to external endpoint after digest email is sent (failsafe, async) + optional open tracking pixel + debug logs
# version: 1.6.1
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "cgi"
  require "time"

  module ::DigestReport
    PLUGIN_NAME = "digest-report2"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php" # postback after send

    # ===== Open tracking switch =====
    OPEN_TRACKING_ENABLED = true

    # Tracking pixel endpoint (must return an actual tiny image)
    #
    # IMPORTANT:
    # Use NO-extension route to avoid nginx/static handling for *.gif
    #   https://forum.example.com/digest/open?email_id=...&user_id=...&user_email=...
    #
    # If you still want legacy, your pixel plugin can keep /digest/open.gif too,
    # but this plugin will now use /digest/open.
    OPEN_TRACKING_PIXEL_BASE_URL = "#{Discourse.base_url}/digest/open"

    # If we can't find an email_id in any link, use this
    DEFAULT_EMAIL_ID = "99999999"

    # ===== DEBUG LOGGING =====
    DEBUG_LOG = true

    # POST field names
    EMAIL_ID_FIELD              = "email_id"            # now extracted from existing links (no generation)
    OPEN_TRACKING_USED_FIELD    = "open_tracking_used"  # "1" or "0"

    TOPIC_IDS_FIELD             = "topic_ids"           # CSV in EMAIL ORDER
    TOPIC_COUNT_FIELD           = "topic_ids_count"     # integer
    FIRST_TOPIC_ID_FIELD        = "first_topic_id"      # first topic id in email order (string)

    SUBJECT_FIELD               = "subject"
    SUBJECT_PRESENT_FLD         = "subject_present"

    FROM_EMAIL_FIELD            = "from_email"

    USER_ID_FIELD               = "user_id"
    USERNAME_FIELD              = "username"
    USER_CREATED_AT_FIELD       = "user_created_at_utc" # ISO8601

    # keep strings sane
    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    # Timeouts
    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    # Sidekiq retry count
    JOB_RETRY_COUNT = 2
    # =========================

    # PluginStore keys (used only as a best-effort fallback)
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
        return txt  unless txt.to_s.empty?
      end

      begin
        message.body&.decoded.to_s
      rescue StandardError
        ""
      end
    end

    # Extract first recipient email safely
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

    # Extract topic IDs in FIRST-SEEN ORDER in the email.
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

    # Extract email_id from FIRST link that contains email_id=...
    def self.extract_email_id_from_message(message)
      body = extract_email_body(message)
      return "" if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s) # turns &amp; into &
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

        # Try URI parse first
        begin
          uri = URI.parse(u)
          q = uri.query.to_s

          # Sometimes stuff is in fragment
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
          # fallback regex below
        end

        # Fallback: raw regex
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

    # Build tracking pixel HTML (safe, tiny, hidden)
    def self.build_tracking_pixel_html(email_id:, user_id:, user_email:)
      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      return "" if base.empty?
      return "" if email_id.to_s.strip.empty? # IMPORTANT: must have extracted email_id

      q = {
        "email_id"   => email_id.to_s,
        "user_id"    => user_id.to_s,
        "user_email" => user_email.to_s
      }

      url =
        begin
          uri = URI.parse(base)
          existing = uri.query.to_s
          add = URI.encode_www_form(q)
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{base}?#{URI.encode_www_form(q)}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end

    # UPDATED: treat either /digest/open OR /digest/open.gif as "already has pixel"
    def self.message_already_has_pixel?(mail_message)
      b = extract_email_body(mail_message)
      return false if b.to_s.empty?

      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      legacy = base.end_with?("/digest/open") ? (base + ".gif") : "#{Discourse.base_url}/digest/open.gif"

      b.include?(base) || b.include?(legacy)
    rescue StandardError
      false
    end

    # Inject tracking pixel into a Mail::Message (multipart or not).
    # Returns true if injection succeeded.
    def self.inject_pixel_into_mail!(mail_message, email_id:, user_id:, user_email:)
      return false if mail_message.nil?

      pixel = build_tracking_pixel_html(email_id: email_id, user_id: user_id, user_email: user_email)
      if pixel.to_s.empty?
        dlog("inject: pixel html empty (likely missing email_id) -> fail")
        return false
      end

      begin
        if mail_message.respond_to?(:multipart?) && mail_message.multipart?
          hp = mail_message.html_part rescue nil
          if hp.nil?
            dlog("inject: multipart but html_part=nil -> fail")
            return false
          end

          html = (hp.body.decoded.to_s rescue "")
          if html.to_s.empty?
            dlog("inject: html_part body empty -> fail")
            return false
          end

          new_html =
            if html.include?("</body>")
              html.sub("</body>", "#{pixel}</body>")
            else
              html + pixel
            end

          hp.body = new_html rescue nil
          dlog("inject: OK via html_part (len=#{html.length})")
          return true
        end
      rescue StandardError => e
        dlog_error("inject: multipart path error err=#{e.class}: #{e.message}")
      end

      begin
        ct = (mail_message.content_type.to_s rescue "")
        unless ct.downcase.include?("text/html")
          dlog("inject: not multipart and content_type not html ct=#{ct.inspect} -> fail")
          return false
        end

        html = (mail_message.body.decoded.to_s rescue "")
        if html.to_s.empty?
          dlog("inject: non-multipart html body empty -> fail")
          return false
        end

        new_html =
          if html.include?("</body>")
            html.sub("</body>", "#{pixel}</body>")
          else
            html + pixel
          end

        mail_message.body = new_html rescue nil
        dlog("inject: OK via body (len=#{html.length})")
        return true
      rescue StandardError => e
        dlog_error("inject: non-multipart path error err=#{e.class}: #{e.message}")
      end

      false
    rescue StandardError => e
      dlog_error("inject: crash err=#{e.class}: #{e.message}")
      false
    end
  end

  # =========================
  # BEFORE send: extract email_id from existing links + inject pixel + stamp headers ✅
  # =========================
  DiscourseEvent.on(:before_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      existing_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      if !existing_id.empty?
        ::DigestReport.dlog("before_email_send: already stamped email_id=#{existing_id} -> skip")
        next
      end

      recipient = ::DigestReport.first_recipient_email(message)

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end
      uid = user ? user.id : 0

      email_id = ::DigestReport.extract_email_id_from_message(message)

      # Best-effort fallback: last stored id for this user
      if email_id.to_s.strip.empty? && uid > 0
        email_id = ::DigestReport.get_last_email_id_for_user(uid)
      end

      # FINAL fallback: fixed constant
      if email_id.to_s.strip.empty?
        email_id = ::DigestReport::DEFAULT_EMAIL_ID
        ::DigestReport.dlog("before_email_send: email_id not found -> using DEFAULT_EMAIL_ID=#{email_id}")
      end

      injected = false
      if ::DigestReport.open_tracking_enabled?
        if ::DigestReport.message_already_has_pixel?(message)
          ::DigestReport.dlog("before_email_send: pixel already present -> injected=true (skip)")
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

      # Store only if it's not the default placeholder
      if uid > 0 && !email_id.to_s.strip.empty? && email_id.to_s != ::DigestReport::DEFAULT_EMAIL_ID
        ::DigestReport.store_last_email_id_for_user(uid, email_id)
      end

      ::DigestReport.dlog(
        "before_email_send: digest to=#{recipient.inspect} user_id=#{uid} extracted_email_id=#{email_id.inspect} injected=#{injected} open_used=#{open_used} " \
        "content_type=#{(message.content_type.to_s rescue '').inspect} multipart=#{(message.multipart? rescue 'n/a')}"
      )
    rescue StandardError => e
      ::DigestReport.dlog_error("before_email_send error err=#{e.class}: #{e.message}")
    end
  end

  # =========================
  # Postback job (uses DEFAULT_EMAIL_ID if missing)
  # =========================
  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url = ::DigestReport::ENDPOINT_URL.to_s.strip

        email_id = args[:email_id].to_s.strip
        if email_id.empty?
          email_id = ::DigestReport::DEFAULT_EMAIL_ID
          ::DigestReport.log_error("Missing email_id in job args -> using DEFAULT_EMAIL_ID=#{email_id}")
        end

        open_tracking_used = args[:open_tracking_used].to_s.strip
        open_tracking_used = "0" unless open_tracking_used == "1"

        user_email = args[:user_email].to_s.strip
        ::DigestReport.log_error("Missing user_email in job args; sending anyway with blank user_email") if user_email.empty?

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

        uri = (URI.parse(url) rescue nil)
        if uri.nil?
          ::DigestReport.log_error("Invalid ENDPOINT_URL #{url.inspect}")
          return
        end

        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          ::DigestReport.log_error("Invalid ENDPOINT_URL scheme (must be http/https): #{url.inspect}")
          return
        end

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
          [::DigestReport::FIRST_TOPIC_ID_FIELD, first_topic_id]
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

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        begin
          res = http.start { |h| h.request(req) }
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

          code = res.code.to_i
          if code >= 200 && code < 300
            ::DigestReport.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id.inspect} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} first_topic_id=#{first_topic_id}")
          else
            ::DigestReport.log_error("POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id.inspect} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} body=#{res.body.to_s[0, 500].inspect}")
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error("POST ERROR ms=#{ms} email_id=#{email_id.inspect} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} err=#{e.class}: #{e.message}")
        ensure
          begin
            http.finish if http.started?
          rescue StandardError
          end
        end
      rescue StandardError => e
        ::DigestReport.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  # =========================
  # After email send: enqueue postback (prefers stamped header; re-extracts if missing)
  # =========================
  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      ::DigestReport.dlog("after_email_send: email_type=#{email_type.inspect} to=#{Array(message&.to).first.to_s.inspect} subject=#{message&.subject.to_s[0, 80].inspect}")
      ::DigestReport.dlog("after_email_send: hdr email_id=#{::DigestReport.header_val(message,'X-Digest-Report-Email-Id').inspect} open=#{::DigestReport.header_val(message,'X-Digest-Report-Open-Tracking-Used').inspect} user_id=#{::DigestReport.header_val(message,'X-Digest-Report-User-Id').inspect}")

      recipient = ::DigestReport.first_recipient_email(message)

      subject =
        begin
          ::DigestReport.safe_str(message&.subject, ::DigestReport::SUBJECT_MAX_LEN)
        rescue StandardError
          ""
        end

      from_email =
        begin
          Array(message&.from).first.to_s.strip
        rescue StandardError
          ""
        end

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end

      uid = user ? user.id : 0
      user_id = user ? user.id : ""
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)

      email_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      if email_id.to_s.strip.empty?
        email_id = ::DigestReport.extract_email_id_from_message(message)
        if email_id.to_s.strip.empty? && uid > 0
          email_id = ::DigestReport.get_last_email_id_for_user(uid)
        end
      end

      if email_id.to_s.strip.empty?
        email_id = ::DigestReport::DEFAULT_EMAIL_ID
        ::DigestReport.dlog("after_email_send: email_id missing -> using DEFAULT_EMAIL_ID=#{email_id}")
      end

      open_tracking_used = ::DigestReport.header_val(message, "X-Digest-Report-Open-Tracking-Used")
      open_tracking_used = (open_tracking_used == "1" ? "1" : "0")

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
        topic_ids: topic_ids
      )

      first_topic_id = topic_ids[0] ? topic_ids[0].to_s : ""
      ::DigestReport.log("Enqueued postback email_id=#{email_id.inspect} open_tracking_used=#{open_tracking_used} user_found=#{!user.nil?} topic_ids_count=#{topic_ids.length} first_topic_id=#{first_topic_id}")
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
