package com.qa.utils;

import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.mail.*;
import jakarta.mail.internet.*;

import java.io.File;
import java.io.InputStream;
import java.time.LocalTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Email manager with:
 * - HTML + multipart extraction (so OTP in HTML-only emails is read)
 * - Tolerant subject/sender matching (contains/blank = wildcard)
 * - Prefers UNREAD mail and uses a tight recency skew so we don't reuse prior OTPs
 * - Strict OTP length using SecKeys.OTP_LENGTH with keyword proximity scoring
 */
public class EmailManager {

    // ---- Config keys (avoid magic strings) ----
    private static final String KEY_MAIL_USERNAME   = SecureConfig.value(SecKeys.MAIL_USERNAME);
    private static final String KEY_MAIL_PASSWORD   = SecureConfig.value(SecKeys.MAIL_PASSWORD);
    private static final String KEY_MAIL_PROVIDER   = SecureConfig.value(SecKeys.MAIL_PROVIDER);
    private static final String KEY_MAIL_TO         = SecureConfig.value(SecKeys.MAIL_TO);
    private static final String KEY_MAIL_CC         = SecureConfig.value(SecKeys.EMAIL_CC);
    private static final String KEY_OTP_SUBJECT     = SecureConfig.value(SecKeys.OTP_SUBJECT);
    private static final String KEY_OTP_SENDER      = SecureConfig.value(SecKeys.OTP_SENDEREMAIL);
    private static final String KEY_OTP_TAIL_WINDOW = SecureConfig.value(SecKeys.OTP_TAIL_WINDOW);
    private static final String KEY_OTP_LENGTH      = SecureConfig.value(SecKeys.OTP_LENGTH);

    // ---- Providers / SMTP ----
    private static final String PROVIDER_GMAIL    = "gmail";
    private static final String PROVIDER_OUTLOOK  = "outlook";
    private static final String SMTP_HOST_GMAIL   = "smtp.gmail.com";
    private static final String SMTP_HOST_O365    = "smtp.office365.com";
    private static final String SMTP_PORT_TLS     = "587";

    // ---- IMAP / Store ----
    private static final String IMAP_HOST_GMAIL       = "imap.gmail.com";
    private static final int    IMAP_PORT_SSL         = 993;
    private static final String PROTOCOL_IMAPS        = "imaps";
    private static final String PROP_STORE_PROTOCOL   = "mail.store.protocol";
    private static final String PROP_IMAPS_SSL_ENABLE = "mail.imaps.ssl.enable";

    // ---- OTP defaults ----
    private static final int  OTP_TIMEOUT_MINUTES = 3;   // a touch more forgiving
    private static final int  OTP_TAIL_DEFAULT    = 120;
    private static final int  OTP_TAIL_MIN        = 20;
    private static final long RETRY_SLEEP_MS      = 5_000L;
    private static final int  OTP_LEN_DEFAULT     = 4;   // default to 4
    private static final int  OTP_LEN_MIN         = 3;
    private static final int  OTP_LEN_MAX         = 10;

    // Recency skew (kept tight to avoid picking an older OTP on a second scenario run)
    private static final long RECENT_SKEW_MS      = 30_000L;

    // Small holder for SMTP config
    private record SmtpConfig(String host, String port) {}

    /** Holder for IMAP resources with proper try-with-resources support */
    private static final class ImapContext implements AutoCloseable {
        private final Store store;
        private final Folder inbox;
        private boolean expungeOnClose = false; // default for read flow

        ImapContext(Store store, Folder inbox) {
            this.store = store;
            this.inbox = inbox;
        }

        Folder inbox() { return inbox; }

        /** For delete flow: request expunge on close (no param since it's always set to true by callers). */
        void enableExpungeOnClose() { this.expungeOnClose = true; }

        @Override
        public void close() {
            try {
                if (inbox != null && inbox.isOpen()) {
                    inbox.close(expungeOnClose);
                }
            } catch (MessagingException e) {
                TestUtils.log().fatal("Failed to close IMAP inbox: {}", e.getMessage());
            } finally {
                try {
                    if (store != null && store.isConnected()) {
                        store.close();
                    }
                } catch (MessagingException e) {
                    TestUtils.log().fatal("Failed to close IMAP store: {}", e.getMessage());
                }
            }
        }
    }

    // -------------------- SEND --------------------

    public static void sendEmailWithAttachments(String subject, String body, File[] attachments) {
        try {
            String provider  = Objects.toString(KEY_MAIL_PROVIDER, "").toLowerCase(Locale.ROOT);
            List<String> toList = splitEmails(KEY_MAIL_TO);
            List<String> ccList = splitEmails(KEY_MAIL_CC);

            if (isBlank(KEY_MAIL_USERNAME) || isBlank(KEY_MAIL_PASSWORD) || toList.isEmpty()) {
                TestUtils.log().error("Missing email configuration. Check MAIL_USERNAME / MAIL_PASSWORD / MAIL_TO.");
                return;
            }

            SmtpConfig smtp = resolveSmtp(provider);
            Session session = buildSmtpSession(smtp.host(), smtp.port(), KEY_MAIL_USERNAME, KEY_MAIL_PASSWORD);

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(KEY_MAIL_USERNAME));
            message.setRecipients(Message.RecipientType.TO, toAddresses(toList));
            InternetAddress[] ccAddresses = toAddresses(ccList);
            if (ccAddresses.length > 0) {
                message.setRecipients(Message.RecipientType.CC, ccAddresses);
            }
            message.setSubject(subject);

            Multipart multipart = new MimeMultipart("mixed");
            MimeBodyPart bodyPart = new MimeBodyPart();
            bodyPart.setContent(body, "text/html; charset=UTF-8");
            multipart.addBodyPart(bodyPart);
            addAttachments(multipart, attachments);
            message.setContent(multipart);

            Transport.send(message);
            TestUtils.log().info("Email sent successfully via {}", provider.toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            TestUtils.log().fatal("Failed to send email: {}", e.toString());
        }
    }

    // -------------------- READ OTP --------------------

    public static String readOtpFromInbox() {
        String subjectLine = KEY_OTP_SUBJECT;
        String senderEmail = KEY_OTP_SENDER;
        int    otpLen      = resolveOtpLength();

        int  tailWindow    = resolveTailWindow();
        long deadline      = System.currentTimeMillis() + (OTP_TIMEOUT_MINUTES * 60_000L);
        Date testStartTime = new Date();

        Properties props = new Properties();
        props.put(PROP_STORE_PROTOCOL, PROTOCOL_IMAPS);
        props.put(PROP_IMAPS_SSL_ENABLE, "true");

        try (ImapContext ctx = openImapContext(props, KEY_MAIL_USERNAME, KEY_MAIL_PASSWORD)) {
            return scanForOtpUntilTimeout(ctx.inbox(), tailWindow, testStartTime, subjectLine, senderEmail, deadline, otpLen);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new OtpReadException("Thread interrupted while waiting for OTP.", ie);
        } catch (MessagingException me) {
            throw new OtpReadException("Mail error while reading OTP: " + me.getMessage(), me);
        }
    }

    private static ImapContext openImapContext(Properties props, String user, String pass)
            throws MessagingException {
        Session session = Session.getInstance(props);
        Store store = session.getStore(PROTOCOL_IMAPS);
        store.connect(IMAP_HOST_GMAIL, IMAP_PORT_SSL, user, pass);
        TestUtils.log().info("Connected to Gmail successfully");

        Folder inbox = store.getFolder("INBOX");
        inbox.open(Folder.READ_WRITE); // mark messages as read
        TestUtils.log().info("INBOX opened. Total messages={}, Unread={}", inbox.getMessageCount(), inbox.getUnreadMessageCount());
        return new ImapContext(store, inbox);
    }

    private static String scanForOtpUntilTimeout(
            Folder inbox,
            int tailWindow,
            Date testStartTime,
            String subjectLine,
            String senderEmail,
            long deadline,
            int otpLen
    ) throws MessagingException, InterruptedException {

        while (System.currentTimeMillis() < deadline) {
            int total = inbox.getMessageCount();
            if (total <= 0) {
                TestUtils.log().info("Mailbox empty. Will retry...");
                waitBeforeRetry(deadline);
                continue;
            }

            int start = Math.max(1, total - tailWindow + 1);
            Message[] messages = fetchRecentMessages(inbox, start, total);
            TestUtils.log().info("Scanning last {} message(s) (range {}-{}) for OTP...", messages.length, start, total);

            Optional<String> maybeOtp = tryExtractOtpFromMessages(messages, testStartTime, subjectLine, senderEmail, otpLen);
            if (maybeOtp.isPresent()) return maybeOtp.get();

            TestUtils.log().info("OTP not found yet. Will retry...");
            waitBeforeRetry(deadline);
        }

        throw new OtpReadException("OTP email not received within " + OTP_TIMEOUT_MINUTES + " minutes.");
    }

    private static Message[] fetchRecentMessages(Folder inbox, int start, int end) throws MessagingException {
        if (end < start) return new Message[0];
        Message[] messages = inbox.getMessages(start, end);

        FetchProfile fp = new FetchProfile();
        fp.add(FetchProfile.Item.ENVELOPE);
        fp.add(FetchProfile.Item.FLAGS);
        inbox.fetch(messages, fp);
        return messages;
    }

    /**
     * New logic:
     * 1) Partition into UNREAD and READ
     * 2) Scan UNREAD newest→oldest
     * 3) If none match, scan READ newest→oldest (still bounded by recency)
     */
    private static Optional<String> tryExtractOtpFromMessages(
            Message[] messages,
            Date testStartTime,
            String subjectLine,
            String senderEmail,
            int otpLen
    ) {
        final String expectedSubject = subjectLine == null ? "" : subjectLine.trim();
        final String senderNeedle    = senderEmail == null ? "" : senderEmail.toLowerCase(Locale.ROOT);

        List<Message> unread = new ArrayList<>();
        List<Message> read   = new ArrayList<>();
        for (Message m : messages) {
            try {
                if (m.isSet(Flags.Flag.SEEN)) read.add(m); else unread.add(m);
            } catch (MessagingException ignore) {
                read.add(m); // safe fallback
            }
        }

        Optional<String> fromUnread = scanListForOtp(unread, testStartTime, expectedSubject, senderNeedle, otpLen);
        if (fromUnread.isPresent()) return fromUnread;

        return scanListForOtp(read, testStartTime, expectedSubject, senderNeedle, otpLen);
    }

    private static Optional<String> scanListForOtp(
            List<Message> list,
            Date testStartTime,
            String expectedSubject,
            String senderNeedle,
            int otpLen
    ) {
        for (int i = list.size() - 1; i >= 0; i--) { // newest → oldest
            try {
                Optional<String> otp = maybeOtpFromMessage(list.get(i), testStartTime, expectedSubject, senderNeedle, otpLen);
                if (otp.isPresent()) {
                    TestUtils.log().info("OTP extracted and message marked as read");
                    TestUtils.log().info("OTP read time: {}", LocalTime.now());
                    return otp;
                }
            } catch (EmailContentException ece) {
                TestUtils.log().warn("Failed to parse message content: {}", ece.getMessage());
            } catch (MessagingException me) {
                TestUtils.log().warn("Message access error while scanning for OTP: {}", me.getMessage());
            }
        }
        return Optional.empty();
    }

    private static Optional<String> maybeOtpFromMessage(
            Message msg, Date testStartTime, String expectedSubject, String senderNeedle, int otpLen
    ) throws MessagingException, EmailContentException {
        if (!isRecent(msg, testStartTime)) return Optional.empty();
        if (!matchesSubjectAndSender(msg, expectedSubject, senderNeedle)) return Optional.empty();
        Optional<String> otp = extractOtpFromMessage(msg, otpLen);
        if (otp.isPresent()) msg.setFlag(Flags.Flag.SEEN, true);
        return otp;
    }

    // ---- Matching & recency ----

    private static boolean isRecent(Message msg, Date testStartTime) throws MessagingException {
        Date received = msg.getReceivedDate();
        if (received == null) received = msg.getSentDate();
        if (received == null) return true; // unknown timestamps → don't exclude
        // Tight skew to avoid reusing previous scenario's OTP
        return !received.before(new Date(testStartTime.getTime() - RECENT_SKEW_MS));
    }

    private static boolean matchesSubjectAndSender(Message msg, String expectedSubject, String senderNeedle)
            throws MessagingException {
        String subj = Optional.ofNullable(msg.getSubject()).orElse("");
        String subjLc = subj.toLowerCase(Locale.ROOT);
        String expSubLc = Optional.ofNullable(expectedSubject).orElse("").trim().toLowerCase(Locale.ROOT);

        boolean subjectMatches = expSubLc.isBlank() || subjLc.contains(expSubLc);

        Address[] froms = msg.getFrom();
        String from = (froms != null && froms.length > 0) ? froms[0].toString() : "";
        String fromLc = from.toLowerCase(Locale.ROOT);

        boolean senderMatches = isBlank(senderNeedle) || fromLc.contains(senderNeedle);

        TestUtils.log().debug("Checking targeted email");
        return subjectMatches && senderMatches;
    }

    // ---- Content extraction (HTML + multipart aware) ----

    private static Optional<String> extractOtpFromMessage(Message msg, int otpLen) throws EmailContentException {
        String content = getTextFromMessage(msg);
        if (content == null) return Optional.empty();

        content = content.replace('\u00A0', ' ').replaceAll("[ \\t\\x0B\\f\\r]+", " ").trim();

        String otp = extractOtp(content, otpLen);
        return Optional.ofNullable(otp);
    }

    private static String getTextFromMessage(Message message) throws EmailContentException {
        try {
            Object content = message.getContent();
            return extractText(content);
        } catch (Exception e) {
            throw new EmailContentException("Unable to read email content: " + e.getMessage(), e);
        }
    }

    private static String extractText(Object content) throws Exception {
        if (content == null) return null;

        if (content instanceof String s) return s;

        if (content instanceof Multipart mp) {
            StringBuilder plain = new StringBuilder();
            StringBuilder html  = new StringBuilder();

            for (int i = 0; i < mp.getCount(); i++) {
                BodyPart part = mp.getBodyPart(i);
                String partText = extractPart(part, plain, html);
                if (partText != null) return partText; // early win
            }

            if (plain.length() > 0) return plain.toString();
            if (html.length()  > 0) return html.toString();
            return null;
        }

        if (content instanceof DataHandler dh) {
            try (InputStream is = dh.getInputStream(); Scanner sc = new Scanner(is).useDelimiter("\\A")) {
                return sc.hasNext() ? sc.next() : null;
            }
        }

        return content.toString();
    }

    private static String extractPart(BodyPart part, StringBuilder plain, StringBuilder html) throws Exception {
        String ct = Optional.ofNullable(part.getContentType()).orElse("").toLowerCase(Locale.ROOT);

        if (part.isMimeType("text/plain")) {
            Object inner = part.getContent();
            String s = inner != null ? inner.toString() : null;
            if (s != null) {
                plain.append(s);
                if (ct.contains("alternative")) return s;
            }
            return null;
        }

        if (part.isMimeType("text/html")) {
            Object inner = part.getContent();
            String raw = inner != null ? inner.toString() : null;
            if (raw != null) {
                String stripped = raw.replaceAll("(?is)<style.*?</style>", " ")
                        .replaceAll("(?is)<script.*?</script>", " ")
                        .replaceAll("(?s)<[^>]*>", " ")
                        .replace('\u00A0', ' ')
                        .replaceAll("[ \\t\\x0B\\f\\r\\n]+", " ")
                        .trim();
                html.append(stripped);
            }
            return null;
        }

        if (part.isMimeType("multipart/*")) {
            Object inner = part.getContent();
            String nested = extractText(inner);
            if (nested != null && !nested.isBlank()) return nested;
            return null;
        }

        return null;
    }

    // ---- OTP extraction with configured length + keyword proximity ----

    private static String extractOtp(String content, int otpLen) {
        Pattern p = Pattern.compile("(?<!\\d)(\\d{" + otpLen + "})(?!\\d)");
        Matcher m = p.matcher(content);

        List<int[]> matches = new ArrayList<>();
        while (m.find()) matches.add(new int[]{m.start(1), m.end(1)});
        if (matches.isEmpty()) return null;

        String lc = content.toLowerCase(Locale.ROOT);
        List<Integer> keywordPos = findKeywordPositions(lc, List.of(
                "otp", "one-time", "one time", "verification", "verify", "code",
                "passcode", "login", "signin", "sign-in", "pin", "temporar", "auth"
        ));

        if (keywordPos.isEmpty()) {
            int[] pick = matches.get(0);
            return content.substring(pick[0], pick[1]);
        }

        int bestIdx = 0; long bestDist = Long.MAX_VALUE;
        for (int i = 0; i < matches.size(); i++) {
            int center = (matches.get(i)[0] + matches.get(i)[1]) / 2;
            long dist = minDistance(center, keywordPos);
            if (dist < bestDist) { bestDist = dist; bestIdx = i; }
        }
        int[] pick = matches.get(bestIdx);
        return content.substring(pick[0], pick[1]);
    }

    private static List<Integer> findKeywordPositions(String s, List<String> kws) {
        List<Integer> pos = new ArrayList<>();
        for (String kw : kws) {
            int idx = s.indexOf(kw);
            while (idx >= 0) {
                pos.add(idx);
                idx = s.indexOf(kw, idx + 1);
            }
        }
        return pos;
    }

    private static long minDistance(int point, List<Integer> positions) {
        long best = Long.MAX_VALUE;
        for (int p : positions) {
            long d = Math.abs((long) point - p);
            if (d < best) best = d;
        }
        return best;
    }

    // -------------------- DELETE OTP MAILS --------------------

    public static void deleteOtpEmails() {
        String subjectLine = KEY_OTP_SUBJECT;
        String senderEmail = KEY_OTP_SENDER;

        int tailWindow = resolveTailWindow();

        Properties props = new Properties();
        props.put(PROP_STORE_PROTOCOL, PROTOCOL_IMAPS);
        props.put(PROP_IMAPS_SSL_ENABLE, "true");

        try (ImapContext ctx = openImapContext(props, KEY_MAIL_USERNAME, KEY_MAIL_PASSWORD)) {
            Folder inbox = ctx.inbox();

            int total = inbox.getMessageCount();
            if (total == 0) {
                TestUtils.log().warn("Mailbox empty during delete scan.");
                return;
            }

            int start = Math.max(1, total - tailWindow + 1);
            Optional<Message> latestOtpMessage =
                    findLatestReadMatchingMessage(inbox, start, total, subjectLine, senderEmail);

            if (latestOtpMessage.isPresent()) {
                latestOtpMessage.get().setFlag(Flags.Flag.DELETED, true);
                ctx.enableExpungeOnClose(); // expunge when ctx closes
                TestUtils.log().info("Deleted latest read OTP email");
            } else {
                TestUtils.log().warn("No read OTP email found to delete");
            }
        } catch (Exception e) {
            TestUtils.log().fatal("Failed to delete OTP emails: {}", e.getMessage());
        }
    }

    // -------------------- helpers --------------------

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static List<String> splitEmails(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private static InternetAddress[] toAddresses(List<String> emails) {
        return emails.stream()
                .map(EmailManager::toInternetAddressSafe)
                .filter(Objects::nonNull)
                .toArray(InternetAddress[]::new);
    }

    private static InternetAddress toInternetAddressSafe(String email) {
        try { return new InternetAddress(email); }
        catch (AddressException e) {
            TestUtils.log().warn("Invalid email skipped: {}", email);
            return null;
        }
    }

    private static SmtpConfig resolveSmtp(String provider) {
        String p = Objects.toString(provider, "");
        return switch (p) {
            case PROVIDER_OUTLOOK -> new SmtpConfig(SMTP_HOST_O365, SMTP_PORT_TLS);
            case PROVIDER_GMAIL   -> new SmtpConfig(SMTP_HOST_GMAIL, SMTP_PORT_TLS);
            default               -> new SmtpConfig(SMTP_HOST_GMAIL, SMTP_PORT_TLS);
        };
    }

    private static Session buildSmtpSession(String host, String port, String fromEmail, String password) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);

        return Session.getInstance(props, new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(fromEmail, password);
            }
        });
    }

    private static void addAttachments(Multipart multipart, File[] attachments) {
        if (attachments == null || attachments.length == 0) return;

        Stream.of(attachments)
                .filter(Objects::nonNull)
                .filter(File::exists)
                .forEach(file -> {
                    try {
                        MimeBodyPart attach = new MimeBodyPart();
                        DataSource source = new FileDataSource(file);
                        attach.setDataHandler(new DataHandler(source));
                        attach.setFileName(file.getName());
                        multipart.addBodyPart(attach);
                        TestUtils.log().info("Attachment added: {}", file.getName());
                    } catch (MessagingException e) {
                        TestUtils.log().warn("Failed to add attachment {}: {}", file.getName(), e.getMessage());
                    }
                });
    }

    private static int resolveTailWindow() {
        int tailWindow = OTP_TAIL_DEFAULT;
        try {
            String tw = KEY_OTP_TAIL_WINDOW;
            if (!isBlank(tw)) tailWindow = Math.max(OTP_TAIL_MIN, Integer.parseInt(tw.trim()));
        } catch (Exception e) {
            TestUtils.log().warn("Invalid OTP_TAIL_WINDOW value. Falling back to default={}. Reason: {}",
                    OTP_TAIL_DEFAULT, e.getMessage());
        }
        return tailWindow;
    }

    private static int resolveOtpLength() {
        int len = OTP_LEN_DEFAULT;
        try {
            if (!isBlank(KEY_OTP_LENGTH)) len = Integer.parseInt(KEY_OTP_LENGTH.trim());
        } catch (Exception e) {
            TestUtils.log().warn("Invalid OTP_LENGTH value '{}'. Falling back to default={}.", KEY_OTP_LENGTH, OTP_LEN_DEFAULT);
        }
        if (len < OTP_LEN_MIN || len > OTP_LEN_MAX) {
            TestUtils.log().warn("OTP_LENGTH={} out of range ({}-{}). Clamping.", len, OTP_LEN_MIN, OTP_LEN_MAX);
            len = Math.max(OTP_LEN_MIN, Math.min(OTP_LEN_MAX, len));
        }
        return len;
    }

    private static Optional<Message> findLatestReadMatchingMessage(
            Folder inbox, int start, int end, String subjectLine, String senderEmail) throws MessagingException {

        if (end < start) return Optional.empty();

        Message[] messages = inbox.getMessages(start, end);

        FetchProfile fp = new FetchProfile();
        fp.add(FetchProfile.Item.ENVELOPE);
        fp.add(FetchProfile.Item.FLAGS);
        inbox.fetch(messages, fp);

        String senderNeedle = senderEmail == null ? "" : senderEmail.toLowerCase(Locale.ROOT);
        String subjectNeedle = subjectLine == null ? "" : subjectLine.trim().toLowerCase(Locale.ROOT);

        for (int i = messages.length - 1; i >= 0; i--) {
            Message msg = messages[i];
            boolean isRead = msg.isSet(Flags.Flag.SEEN);
            if (isRead) {
                String subj = Optional.ofNullable(msg.getSubject()).orElse("");
                boolean subjectMatches = subjectNeedle.isBlank() || subj.toLowerCase(Locale.ROOT).contains(subjectNeedle);

                Address[] froms = msg.getFrom();
                String from = (froms != null && froms.length > 0) ? froms[0].toString() : "";
                boolean senderMatches = isBlank(senderNeedle) || from.toLowerCase(Locale.ROOT).contains(senderNeedle);

                if (subjectMatches && senderMatches) return Optional.of(msg);
            }
        }

        return Optional.empty();
    }

    // ---- Exceptions ----

    public static class OtpReadException extends RuntimeException {
        public OtpReadException(String message) { super(message); }
        public OtpReadException(String message, Throwable cause) { super(message, cause); }
    }

    public static class EmailContentException extends Exception {
        public EmailContentException(String message, Throwable cause) { super(message, cause); }
    }

    private static void waitBeforeRetry(long deadline) throws InterruptedException {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) return;
        long sleepMs = Math.min(RETRY_SLEEP_MS, remaining);
        TestUtils.log().info("Waiting {} second(s) before retry...", java.util.concurrent.TimeUnit.MILLISECONDS.toSeconds(sleepMs));
        java.util.concurrent.TimeUnit.MILLISECONDS.sleep(sleepMs);
    }
}
