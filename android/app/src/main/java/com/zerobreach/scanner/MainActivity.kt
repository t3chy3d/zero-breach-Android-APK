package com.zerobreach.scanner

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * Zero Breach for Android — a local, read-only port of
 * https://github.com/interplains/zero-breach (v0.1.8 indicator set,
 * as-of 2026-10-18, SHA-256 of the upstream IOC file verified at build time).
 *
 * Same job as the desktop scanner: check this device for traces of the
 * AdFection / Candiru ad-delivered spyware campaign, grade the evidence,
 * and say plainly what could NOT be checked.
 *
 * What Android changes (stated in the report, not hidden):
 *  - Android's sandbox means no app can read Chrome/Brave/Firefox's private
 *    history, cookies or caches. The desktop browser checks therefore run
 *    here only over files/folders the user picks (exports, backups, a
 *    Downloads folder), and direct browser access is reported as a GAP.
 *  - Windows-only checks (per-user COM persistence, HW.sys driver drops,
 *    Windows DNS event log) have no Android equivalent. Their Android
 *    analogues are checked instead: device-admin receivers, enabled
 *    accessibility services, active VPN, Private DNS and DNS servers,
 *    the hosts file, and installed-app APK hashes.
 *  - File hash + content-string checks run over shared storage the user
 *    grants (All-files access or a picked folder), exactly the locations
 *    a dropped payload / saved trace would survive in.
 *
 * No INTERNET permission. No network requests. No telemetry. Read-only.
 */
class MainActivity : Activity() {

    // evidence grades, strongest first — same names/order as upstream
    companion object {
        const val EV_ON_DISK = "on-disk"
        const val EV_PERSISTENCE = "persistence"
        const val EV_CONTACTED = "contacted"
        const val EV_DNS = "dns-record"
        const val EV_CONFIGURED = "configured"
        const val EV_REFERENCED = "referenced"
        val EV_ORDER = listOf(EV_ON_DISK, EV_PERSISTENCE, EV_CONTACTED, EV_DNS, EV_CONFIGURED, EV_REFERENCED)
        const val REQ_FOLDER = 41
        const val REQ_FILES = 42
        const val REQ_STORAGE_PERM = 43
        val HASH_EXTS = setOf("dll", "exe", "sys", "ocx", "cpl", "scr", "tmp", "dat", "bin", "ax", "apk", "dex", "so", "jar")
        const val MAX_HASH_BYTES = 120L * 1024 * 1024
        const val MAX_STRING_BYTES = 25 * 1024 * 1024
    }

    data class Finding(
        val evidence: String, val indicator: Indicator,
        val location: String, val detail: String
    )

    class ScanState(val iocs: IocSet) {
        val findings = ArrayList<Finding>()
        val gaps = LinkedHashMap<String, String>()
        val notes = ArrayList<String>()
        val ran = LinkedHashSet<String>()
        var filesHashed = 0
        var filesSearched = 0
        var filesSkipped = 0
        var appsHashed = 0
    }

    private lateinit var statusView: TextView
    private lateinit var reportView: TextView
    private val ui = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var iocs: IocSet? = null
    @Volatile private var lastReport: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 36, 36, 36)
        }
        fun tv(text: String, size: Float, bold: Boolean = false) = TextView(this).apply {
            this.text = text; textSize = size
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 14 }
        }
        fun btn(text: String, action: () -> Unit) = Button(this).apply {
            this.text = text
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 12 }
            setOnClickListener { action() }
        }

        root.addView(tv("Zero Breach — Android", 22f, true))
        root.addView(tv(
            "Local, read-only check for traces of the AdFection / Candiru " +
            "ad-delivered spyware campaign, using the same published indicator set " +
            "as the desktop Zero Breach scanner (github.com/interplains/zero-breach).\n\n" +
            "A clean result is NOT a clean bill of health. Spyware of this grade is built " +
            "to defeat exactly this kind of check, and most traces expire within weeks. " +
            "This app narrows uncertainty; it does not remove it. If you have real reason " +
            "to believe you are a target, get expert help — the Access Now Digital Security " +
            "Helpline or Amnesty International's Security Lab — not a self-service app.\n\n" +
            "This app has no internet permission, makes no network requests, and changes nothing."
        , 14f))

        root.addView(btn("Run device checks") { startDeviceScan() })
        root.addView(btn("Pick a folder to scan (Downloads, a browser export, a backup…)") {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
            startActivityForResult(intent, REQ_FOLDER)
        })
        root.addView(btn("Pick file(s) to scan") {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE)
                putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
            }
            startActivityForResult(intent, REQ_FILES)
        })
        root.addView(btn("Grant all-files access (for the storage scan)") { openAllFilesSettings() })
        root.addView(btn("Copy report to clipboard") {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Zero Breach report", lastReport))
            status("Report copied.")
        })

        statusView = tv("Loading indicators…", 14f, true); root.addView(statusView)
        reportView = tv("", 13f).apply { setTextIsSelectable(true) }; root.addView(reportView)

        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)

        worker.execute {
            try {
                val loaded = assets.open("adfection_iocs.txt").use { IocSet.load(it) }
                iocs = loaded
                status("Indicators loaded: ${loaded.indicators.size} " +
                    "(${loaded.domains.size} domains, ${loaded.ips.size} IPs, ${loaded.hashes.size} file hashes), " +
                    "curated ${loaded.asOf ?: "unknown date"}. Ready — tap “Run device checks”.")
            } catch (e: Exception) {
                status("Could not load the indicator set: ${e.message}. A scan without indicators would be meaningless, so nothing was run.")
            }
        }
    }

    private fun status(s: String) { ui.post { statusView.text = s } }
    private fun showReport(s: String) { lastReport = s; ui.post { reportView.text = s } }

    private fun openAllFilesSettings() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
                return
            } catch (e: Exception) { /* fall through to the general page */ }
            try { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) } catch (e: Exception) {
                status("Could not open the all-files settings page on this device. You can still scan any folder with “Pick a folder to scan”.")
            }
        } else {
            requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), REQ_STORAGE_PERM)
        }
    }

    private fun ensureIocs(): IocSet? {
        val set = iocs
        if (set == null) status("Indicators are still loading — try again in a moment.")
        return set
    }

    // ---------------------------------------------------------------- scans

    private fun startDeviceScan() {
        val set = ensureIocs() ?: return
        status("Scanning… hosts file, DNS / Private DNS, installed apps, persistence equivalents, shared storage.")
        worker.execute {
            val st = ScanState(set)
            try {
                checkHosts(st)
                checkDns(st)
                checkInstalledApps(st)
                checkPersistenceEquivalents(st)
                scanSharedStorage(st)
                // Standing gaps on Android — measured, never inferred (upstream D3).
                st.gaps["browser/direct"] =
                    "Android's sandbox prevents any app from reading Chrome, Brave, Firefox or other browsers' " +
                    "private history, cookies, caches and storage. Those desktop checks could NOT be run directly. " +
                    "Use “Pick a folder to scan” on a browser export/backup, or on Downloads, to search that data instead."
                st.gaps["dns/history-and-cache"] =
                    "Android exposes no queryable DNS resolver cache or DNS query history to apps, so past lookups " +
                    "cannot be checked retrospectively the way the Windows DNS log can. Only the current DNS / Private DNS configuration was checked."
                st.gaps["host/windows-only"] =
                    "Windows-only desktop checks have no Android equivalent and were not run: per-user COM persistence, " +
                    "the HW.sys vulnerable-driver fixed path, and the Windows DNS-Client event log. Android persistence " +
                    "equivalents (device admins, accessibility services, VPN) were checked instead."
            } catch (e: Exception) {
                st.gaps["scan/error"] = "The device scan stopped early: ${e.message}. Treat the result as partial."
            }
            showReport(buildReport(st, "Device scan"))
            status("Device scan finished: ${st.findings.size} finding(s), ${st.gaps.size} gap(s). Full report below.")
        }
    }

    private fun checkHosts(st: ScanState) {
        var anyReadable = false
        for (path in listOf("/system/etc/hosts", "/etc/hosts")) {
            val f = File(path)
            if (!f.canRead()) continue
            anyReadable = true
            st.ran.add("hosts-file:$path")
            try {
                f.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        val clean = line.substringBefore('#').trim()
                        if (clean.isEmpty()) continue
                        val parts = clean.split(Regex("\\s+"))
                        if (parts.size < 2) continue
                        val ip = parts[0]
                        val blocking = ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "0"
                        for (host in parts.drop(1)) {
                            val ind = st.iocs.matchHostname(host) ?: continue
                            if (blocking) {
                                st.notes.add("hosts-file: $host is mapped to $ip in $path — that is a protective block, not contact.")
                            } else {
                                st.findings.add(Finding(EV_CONFIGURED, ind, "$path: $host -> $ip",
                                    "An indicator name is mapped to a real address in the hosts file."))
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                st.gaps["hosts-file:$path"] = "Hosts file at $path exists but could not be read: ${e.message}"
            }
        }
        if (!anyReadable) st.gaps["hosts-file"] = "No readable hosts file found at /system/etc/hosts or /etc/hosts, so that check could not run."
    }

    private fun checkDns(st: ScanState) {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            var checked = 0
            for (network in cm.allNetworks) {
                val lp = cm.getLinkProperties(network) ?: continue
                for (dns in lp.dnsServers) {
                    checked++
                    val addr = dns.hostAddress ?: continue
                    val ind = st.iocs.byValue[addr.lowercase()]
                    if (ind != null && ind.type == "ip") {
                        st.findings.add(Finding(EV_CONFIGURED, ind, "DNS server $addr",
                            "A current DNS server address is a published indicator IP. Cloud IPs are reassigned over time, so treat an IP-only hit as weaker than a domain hit."))
                    }
                }
                val pdnsName = if (Build.VERSION.SDK_INT >= 28) lp.privateDnsServerName else null
                if (!pdnsName.isNullOrBlank()) {
                    st.iocs.matchHostname(pdnsName)?.let { ind ->
                        st.findings.add(Finding(EV_CONFIGURED, ind, "Private DNS server $pdnsName",
                            "The Private DNS hostname set for a current network matches a published indicator."))
                    }
                }
                val caps = cm.getNetworkCapabilities(network)
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    st.notes.add("network: a VPN is active. Traffic through it is only as trustworthy as its provider; no indicator is implied by a VPN alone.")
                }
            }
            // System-wide Private DNS setting (Android 9+)
            val mode = Settings.Global.getString(contentResolver, "private_dns_mode")
            val spec = Settings.Global.getString(contentResolver, "private_dns_specifier")
            if (!spec.isNullOrBlank()) {
                st.iocs.matchHostname(spec)?.let { ind ->
                    st.findings.add(Finding(EV_CONFIGURED, ind, "Private DNS setting ($mode): $spec",
                        "The device-wide Private DNS hostname matches a published indicator."))
                }
                st.notes.add("dns: Private DNS is set to “$spec” (mode $mode). It did ${if (st.iocs.matchHostname(spec) == null) "not" else ""} match an indicator.")
            }
            if (checked > 0) st.ran.add("dns/config ($checked server address(es))") else {
                st.gaps["dns/config"] = "No active network DNS servers could be read (no network up?), so the DNS configuration check could not run."
            }
        } catch (e: Exception) {
            st.gaps["dns/config"] = "DNS configuration could not be read: ${e.message}"
        }
    }

    private fun checkInstalledApps(st: ScanState) {
        try {
            val hashTargets = st.iocs.hashes.associateBy { it.value }
            val packages = packageManager.getInstalledPackages(0)
            var hashed = 0; var skippedLarge = 0
            for (pkg in packages) {
                val src = pkg.applicationInfo?.sourceDir ?: continue
                val f = File(src)
                if (!f.canRead()) continue
                if (f.length() > MAX_HASH_BYTES) { skippedLarge++; continue }
                try {
                    val digest = sha256(FileInputStream(f))
                    hashed++
                    val ind = hashTargets[digest]
                    if (ind != null) {
                        val label = try { packageManager.getApplicationLabel(pkg.applicationInfo!!).toString() } catch (e: Exception) { pkg.packageName }
                        val detail = if (ind.tier == "sample")
                            "The installed app “$label” (${pkg.packageName}) has the exact SHA-256 of a published spyware sample. Do not delete it yet — preserve the evidence and get expert help."
                        else
                            "The installed app “$label” (${pkg.packageName}) matches the hash of legitimate software this actor is known to abuse. That is a lead to investigate, NOT proof of infection."
                        st.findings.add(Finding(EV_ON_DISK, ind, "$src (${pkg.packageName})", detail))
                    }
                } catch (e: Exception) { st.filesSkipped++ }
            }
            st.appsHashed = hashed
            st.ran.add("apps/apk-hashes ($hashed app file(s) fingerprinted)")
            if (skippedLarge > 0) st.notes.add("apps: $skippedLarge installed app file(s) were over the ${MAX_HASH_BYTES / 1024 / 1024} MB fingerprint cap and were not hash-checked.")
            st.notes.add("apps: ${packages.size} installed packages enumerated. The indicator set contains no Android package names, so apps were checked by file hash only — an app not matching a known hash is not thereby cleared.")
        } catch (e: Exception) {
            st.gaps["apps/apk-hashes"] = "Installed apps could not be enumerated/hashed: ${e.message}"
        }
    }

    private fun checkPersistenceEquivalents(st: ScanState) {
        // Device-admin receivers (Android analogue of auto-start persistence).
        try {
            val intent = Intent("android.app.action.DEVICE_ADMIN_ENABLED")
            val admins = packageManager.queryBroadcastReceivers(intent, PackageManager.GET_META_DATA)
            if (admins.isNotEmpty()) {
                val names = admins.map { it.activityInfo.packageName }.distinct()
                st.notes.add("persistence/device-admin: ${names.size} app(s) declare a device-admin receiver (${names.joinToString(", ")}). Device admin is a powerful persistence position — normal for work/MDM apps, worth knowing about, not a finding by itself.")
            } else st.notes.add("persistence/device-admin: no apps declare a device-admin receiver.")
            st.ran.add("persistence/device-admin")
        } catch (e: Exception) {
            st.gaps["persistence/device-admin"] = "Device-admin receivers could not be enumerated: ${e.message}"
        }
        // Enabled accessibility services.
        try {
            val enabled = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            if (!enabled.isNullOrBlank()) {
                val services = enabled.split(':').filter { it.isNotBlank() }
                st.notes.add("persistence/accessibility: ${services.size} accessibility service(s) are ENABLED (${services.joinToString(", ")}). An enabled accessibility service can read the screen and act on your behalf — legitimate for accessibility tools, a classic spyware position otherwise. This is context, not a finding.")
            } else st.notes.add("persistence/accessibility: no accessibility services are enabled.")
            st.ran.add("persistence/accessibility")
        } catch (e: Exception) {
            st.gaps["persistence/accessibility"] = "Enabled accessibility services could not be read: ${e.message}"
        }
    }

    // ------------------------------------------------------- file scanning

    private fun hasStorageAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun scanSharedStorage(st: ScanState) {
        if (!hasStorageAccess()) {
            st.gaps["storage/shared"] =
                "Shared storage (Downloads, Documents, the internal storage root) could not be walked: all-files access " +
                "is not granted. Tap “Grant all-files access”, or scan the same folders with “Pick a folder to scan”."
            return
        }
        val roots = LinkedHashSet<File>()
        Environment.getExternalStorageDirectory()?.let { roots.add(it) }
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)?.let { roots.add(it) }
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)?.let { roots.add(it) }
        // De-duplicate nested roots (Downloads/Documents live inside the root).
        val kept = roots.filter { r -> roots.none { o -> o != r && r.path.startsWith(o.path + File.separator) } }
        for (root in kept) {
            if (!root.isDirectory) continue
            status("Scanning storage: ${root.path} … (${st.filesHashed} hashed, ${st.filesSearched} searched so far)")
            scanDirectory(st, root, "storage:${root.path}")
            st.ran.add("storage:${root.path}")
        }
    }

    private val pruneDirs = setOf("cache", "cache_data", "gpucache", "code cache", ".git", "node_modules")

    private fun scanDirectory(st: ScanState, root: File, label: String) {
        val stack = ArrayDeque<File>(); stack.add(root)
        var walked = 0
        while (stack.isNotEmpty()) {
            val dir = stack.removeLast()
            val entries = try { dir.listFiles() } catch (e: Exception) { null } ?: continue
            for (entry in entries) {
                if (entry.isDirectory) {
                    if (entry.name.lowercase() !in pruneDirs) stack.add(entry)
                } else if (entry.isFile) {
                    walked++
                    if (walked % 200 == 0) status("Scanning $label … $walked files seen, ${st.findings.size} finding(s) so far.")
                    scanLocalFile(st, entry, entry.path)
                }
            }
        }
    }

    private fun gradeForName(name: String): String {
        val n = name.lowercase()
        val browserish = listOf("history", "cookies", "cache", "leveldb", "local storage",
            "session storage", "service worker", "web data", "places.sqlite", "favicons")
        return if (browserish.any { n.contains(it) }) EV_CONTACTED else EV_REFERENCED
    }

    /** Hash + string scan of one local file. Mirrors upstream: hash candidates by
     *  extension, oversize files are skipped-and-counted, never silently clean. */
    private fun scanLocalFile(st: ScanState, f: File, location: String) {
        val size = try { f.length() } catch (e: Exception) { -1L }
        if (size < 0) { st.filesSkipped++; return }
        val ext = f.name.substringAfterLast('.', "").lowercase()
        if (ext in HASH_EXTS) {
            if (size > MAX_HASH_BYTES) { st.filesSkipped++ }
            else {
                try {
                    val digest = sha256(FileInputStream(f)); st.filesHashed++
                    hashHit(st, digest, location)?.let { st.findings.add(it) }
                } catch (e: Exception) { st.filesSkipped++ }
            }
        }
        if (size in 1..MAX_STRING_BYTES) {
            try {
                FileInputStream(f).use { stringScanStream(st, it, size.toInt(), location, gradeForName(f.name)) }
            } catch (e: Exception) { st.filesSkipped++ }
        } else if (size > MAX_STRING_BYTES) st.filesSkipped++
    }

    private fun hashHit(st: ScanState, digest: String, location: String): Finding? {
        val ind = st.iocs.byValue[digest] ?: return null
        val detail = if (ind.tier == "sample")
            "This file's SHA-256 matches a published spyware sample. Do not delete it — preserve the evidence and get expert help."
        else
            "This file's SHA-256 matches legitimate software this actor is known to abuse (tier: vuln-driver). A lead to investigate, NOT proof of infection."
        return Finding(EV_ON_DISK, ind, location, detail)
    }

    /** Search one stream's bytes for indicator domains/IPs, as plain text and as
     *  UTF-16LE (Chromium storage keeps strings wide, as upstream notes). */
    private fun stringScanStream(st: ScanState, input: InputStream, size: Int, location: String, grade: String) {
        val bytes = ByteArray(size)
        var read = 0
        while (read < size) {
            val n = input.read(bytes, read, size - read)
            if (n < 0) break
            read += n
        }
        if (read == 0) return
        val data = if (read == size) bytes else bytes.copyOf(read)
        st.filesSearched++
        val narrow = String(data, Charsets.ISO_8859_1).lowercase()
        val hits = LinkedHashMap<String, Indicator>()
        for (ind in st.iocs.searchText(narrow)) hits[ind.value] = ind
        if (data.size >= 2) {
            val wide = String(data, Charsets.UTF_16LE).lowercase()
            for (ind in st.iocs.searchText(wide)) hits[ind.value] = ind
        }
        for (ind in hits.values) {
            val detail = when (grade) {
                EV_CONTACTED -> "An indicator appears in a browser-type artifact (history/cookies/cache/storage). " +
                    "That is a connection record: its weight depends on the indicator's role (ad delivery vs command-and-control). It does not by itself prove infection."
                else -> "An indicator appears in saved content. That is a reference — it may be an article about the campaign, " +
                    "a saved page or a document — and does not establish that this device contacted the server."
            }
            st.findings.add(Finding(grade, ind, location, detail))
        }
    }

    private fun sha256(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(1024 * 1024)
        input.use { while (true) { val n = it.read(buf); if (n < 0) break; md.update(buf, 0, n) } }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    // ------------------------------------------------------------ SAF scans

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data == null) return
        val set = ensureIocs() ?: return
        when (requestCode) {
            REQ_FOLDER -> {
                val treeUri = data.data ?: return
                try { contentResolver.takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION) } catch (e: Exception) {}
                status("Scanning the picked folder…")
                worker.execute {
                    val st = ScanState(set)
                    try { scanTree(st, treeUri) } catch (e: Exception) {
                        st.gaps["picked-folder"] = "The picked folder could not be fully scanned: ${e.message}"
                    }
                    st.gaps["browser/direct"] = "Direct browser-database access is blocked by Android's sandbox; this scan covers only the folder you picked."
                    showReport(buildReport(st, "Picked-folder scan"))
                    status("Folder scan finished: ${st.findings.size} finding(s). Full report below.")
                }
            }
            REQ_FILES -> {
                val uris = ArrayList<Uri>()
                data.data?.let { uris.add(it) }
                data.clipData?.let { cd -> for (i in 0 until cd.itemCount) uris.add(cd.getItemAt(i).uri) }
                if (uris.isEmpty()) return
                status("Scanning ${uris.size} picked file(s)…")
                worker.execute {
                    val st = ScanState(set)
                    for (uri in uris) scanPickedFile(st, uri)
                    st.ran.add("picked-files (${uris.size})")
                    showReport(buildReport(st, "Picked-file scan"))
                    status("File scan finished: ${st.findings.size} finding(s). Full report below.")
                }
            }
        }
    }

    private fun displayName(uri: Uri): String {
        var name = uri.lastPathSegment ?: uri.toString()
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) name = c.getString(0) ?: name
            }
        } catch (e: Exception) {}
        return name
    }

    private fun scanPickedFile(st: ScanState, uri: Uri) {
        val name = displayName(uri)
        var size = -1L
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) size = c.getLong(0)
            }
        } catch (e: Exception) {}
        // Picked files are explicit user choices: hash every one of them, any type.
        if (size in 1..MAX_HASH_BYTES || size == -1L) {
            try {
                contentResolver.openInputStream(uri)?.let { input ->
                    val digest = sha256(input); st.filesHashed++
                    hashHit(st, digest, "$name ($uri)")?.let { st.findings.add(it) }
                }
            } catch (e: Exception) { st.filesSkipped++ }
        }
        if (size in 1..MAX_STRING_BYTES) {
            try {
                contentResolver.openInputStream(uri)?.use { input ->
                    stringScanStream(st, input, size.toInt(), "$name ($uri)", gradeForName(name))
                }
            } catch (e: Exception) { st.filesSkipped++ }
        } else if (size > MAX_STRING_BYTES) {
            st.notes.add("picked-file: “$name” is over the ${MAX_STRING_BYTES / 1024 / 1024} MB content-search cap and was only hash-checked (if in range).")
        }
    }

    private fun scanTree(st: ScanState, treeUri: Uri) {
        val rootId = DocumentsContract.getTreeDocumentId(treeUri)
        val stack = ArrayDeque<String>(); stack.add(rootId)
        var seen = 0
        while (stack.isNotEmpty()) {
            val parentId = stack.removeLast()
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
            val cursor: Cursor? = try {
                contentResolver.query(childrenUri, arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE
                ), null, null, null)
            } catch (e: Exception) { null }
            if (cursor == null) { st.filesSkipped++; continue }
            cursor.use {
                while (it.moveToNext()) {
                    val docId = it.getString(0) ?: continue
                    val name = it.getString(1) ?: docId
                    val mime = it.getString(2) ?: ""
                    val size = if (it.isNull(3)) -1L else it.getLong(3)
                    if (mime == DocumentsContract.Document.MIME_TYPE_DIR) { stack.add(docId); continue }
                    seen++
                    if (seen % 200 == 0) status("Scanning picked folder… $seen files seen, ${st.findings.size} finding(s) so far.")
                    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                    val fake = UriFile(docUri, name, size)
                    scanPickedUriAsFile(st, fake)
                }
            }
        }
        st.ran.add("picked-folder ($seen file(s))")
    }

    private data class UriFile(val uri: Uri, val name: String, val size: Long)

    private fun scanPickedUriAsFile(st: ScanState, f: UriFile) {
        val ext = f.name.substringAfterLast('.', "").lowercase()
        if (ext in HASH_EXTS && f.size in 1..MAX_HASH_BYTES) {
            try {
                contentResolver.openInputStream(f.uri)?.let { input ->
                    val digest = sha256(input); st.filesHashed++
                    hashHit(st, digest, "${f.name} (${f.uri})")?.let { st.findings.add(it) }
                }
            } catch (e: Exception) { st.filesSkipped++ }
        }
        if (f.size in 1..MAX_STRING_BYTES) {
            try {
                contentResolver.openInputStream(f.uri)?.use { input ->
                    stringScanStream(st, input, f.size.toInt(), "${f.name} (${f.uri})", gradeForName(f.name))
                }
            } catch (e: Exception) { st.filesSkipped++ }
        } else if (f.size > MAX_STRING_BYTES) st.filesSkipped++
    }

    // -------------------------------------------------------------- report

    private fun buildReport(st: ScanState, title: String): String {
        val sb = StringBuilder()
        val set = st.iocs
        sb.appendLine("================================================================")
        sb.appendLine("  Zero Breach 1.0.0 (Android) — AdFection / Candiru indicator check")
        sb.appendLine("  Same indicator set as desktop Zero Breach v0.1.8: ${set.indicators.size} indicators")
        sb.appendLine("  (${set.domains.size} domains, ${set.ips.size} IPs, ${set.hashes.size} file hashes), curated ${set.asOf ?: "unknown"}.")
        sb.appendLine("  $title — ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(java.util.Date())}")
        sb.appendLine("  Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        sb.appendLine("================================================================")
        sb.appendLine("  SUMMARY — read this part")
        sb.appendLine("================================================================")
        if (st.findings.isEmpty()) {
            sb.appendLine("  RESULT: no known indicator was found in anything that could be checked.")
            sb.appendLine()
            sb.appendLine("  This is NOT a clean bill of health. See what could not be")
            sb.appendLine("  checked below — on Android that list is longer than on desktop,")
            sb.appendLine("  because the sandbox blocks direct browser checks.")
        } else {
            sb.appendLine("  RESULT: ${st.findings.size} finding(s). Strongest evidence first.")
            sb.appendLine("  A hit means “investigate”, never by itself “you are compromised” —")
            sb.appendLine("  except a spyware-sample file hash, which identifies that sample.")
            sb.appendLine("  Do NOT delete evidence before an expert has seen it.")
        }
        sb.appendLine()
        sb.appendLine("  CHECKED: ${if (st.ran.isEmpty()) "nothing completed" else st.ran.joinToString("; ")}")
        sb.appendLine("  Files fingerprinted (SHA-256): ${st.filesHashed + st.appsHashed} · content-searched: ${st.filesSearched} · skipped/unreadable/too large: ${st.filesSkipped}")
        if (st.gaps.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("  WHAT COULD NOT BE CHECKED (${st.gaps.size} gap(s))")
            for ((k, v) in st.gaps) sb.appendLine("    - $k: $v")
        }
        if (st.notes.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("  NOTES (context, not findings)")
            for (n in st.notes) sb.appendLine("    - $n")
        }
        if (st.findings.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("================================================================")
            sb.appendLine("  FINDINGS (strongest first; domains/IPs defanged)")
            sb.appendLine("================================================================")
            val sorted = st.findings.sortedWith(compareBy({ EV_ORDER.indexOf(it.evidence) }, { it.indicator.value }))
            for (f in sorted) {
                sb.appendLine()
                sb.appendLine(">> [${f.evidence}] ${set.defang(f.indicator.value)}")
                sb.appendLine("   tier: ${f.indicator.tier} · confidence: ${f.indicator.confidence} · source: ${f.indicator.source}")
                sb.appendLine("   where: ${f.location}")
                sb.appendLine("   what it means: ${f.detail}")
                sb.appendLine("   what to do: ${nextStep(f)}")
            }
        }
        sb.appendLine()
        sb.appendLine("----------------------------------------------------------------")
        sb.appendLine("Indicators: Citizen Lab “Exposing AdFection” (2026), Confiant ADINT (2026),")
        sb.appendLine("Recorded Future (2025), Microsoft / ESET / Avast / Google TAG / Amnesty on")
        sb.appendLine("Candiru / DevilsTongue. Indicator data CC0; this port Apache-2.0, from")
        sb.appendLine("github.com/interplains/zero-breach. Not affiliated with or endorsed by")
        sb.appendLine("Citizen Lab, Confiant, Recorded Future, Amnesty or Access Now.")
        sb.appendLine("Expert help: Access Now Digital Security Helpline; Amnesty Security Lab.")
        return sb.toString()
    }

    private fun nextStep(f: Finding): String = when (f.evidence) {
        EV_ON_DISK -> if (f.indicator.tier == "sample")
            "Preserve the file exactly as-is and contact a digital-security helpline promptly for expert review."
        else "Check what installed/uses this file and when it appeared; treat as a lead, not proof."
        EV_PERSISTENCE -> "Identify what registered this and when; if you don't recognise it, get expert review before removing anything."
        EV_CONTACTED -> "Check the saved context around the record (date, site, app). More concerning infrastructure (cc/validator tiers) warrants expert interpretation."
        EV_CONFIGURED, EV_DNS -> "Check who set this configuration and when. If you didn't set it, treat it as worth expert review."
        else -> "Check the context it was saved in — a reference alone (e.g. an article about the campaign) is not contact."
    }
}
