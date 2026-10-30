package com.zerobreach.scanner

import java.io.InputStream

/**
 * IOC loading + boundary matching, ported from upstream zero-breach
 * scan/adint_scan/iocs.py (Apache-2.0). Same rules:
 *  - type inferred from shape: 64 hex = sha256, dotted quad / IPv6 = ip, else domain
 *  - a match must sit on a boundary: "notcontrolium.net" and
 *    "controlium.network" do NOT match "controlium.net", and
 *    "152.174.65.771" does not match "52.174.65.77"
 *  - a parent domain whose every hit is just the tail of a matched child
 *    ("powerium.net" inside "noas.powerium.net") is one contact, not two
 * Matching is plain text comparison only. Nothing here resolves or
 * contacts an indicator, ever.
 */
data class Indicator(
    val value: String,
    val tier: String,
    val confidence: String,
    val source: String,
    val type: String // "domain" | "ip" | "sha256"
)

class IocSet(val indicators: List<Indicator>, val asOf: String?) {
    val byValue: Map<String, Indicator> = indicators.associateBy { it.value }
    val domains = indicators.filter { it.type == "domain" }
    val ips = indicators.filter { it.type == "ip" }
    val hashes = indicators.filter { it.type == "sha256" }
    val network = indicators.filter { it.type == "domain" || it.type == "ip" }

    fun defang(v: String): String =
        if (v.contains('.') && !v.all { it in "0123456789abcdef" && v.length == 64 }) v.replace(".", "[.]") else v

    private val label = "abcdefghijklmnopqrstuvwxyz0123456789-".toSet()
    private val leftBad = label + '_'
    private val rightBad = label + '_'
    private val digit = "0123456789".toSet()
    private val digitDot = digit + '.'
    private val hexColon = "0123456789abcdef:".toSet()

    private fun badSets(ind: Indicator): Triple<Set<Char>, Set<Char>, Set<Char>> =
        if (ind.type == "ip") {
            if (ind.value.contains(':')) Triple(hexColon + '.', hexColon, hexColon)
            else Triple(digitDot, digit, digit)
        } else Triple(leftBad, rightBad, label)

    /** All start offsets where [ind] occurs in [hayLower] (already lower-cased) on a real boundary. */
    fun positions(hayLower: String, ind: Indicator): List<Int> {
        val (lb, rb, cont) = badSets(ind)
        val needle = ind.value
        val out = ArrayList<Int>()
        var start = 0
        while (true) {
            val idx = hayLower.indexOf(needle, start)
            if (idx < 0) return out
            val before = if (idx > 0) hayLower[idx - 1] else null
            val afterPos = idx + needle.length
            val after = if (afterPos < hayLower.length) hayLower[afterPos] else null
            var ok = before == null || before !in lb
            if (ok && after != null) {
                if (after in rb) ok = false
                else if (after == '.') {
                    val nxt = if (afterPos + 1 < hayLower.length) hayLower[afterPos + 1] else null
                    ok = nxt == null || nxt !in cont
                }
            }
            if (ok) out.add(idx)
            start = idx + 1
        }
    }

    /** Indicators genuinely present in [hayLower], parent-domains pruned as upstream does. */
    fun searchText(hayLower: String): List<Indicator> {
        val found = ArrayList<Pair<Indicator, List<Int>>>()
        for (ind in network) {
            if (hayLower.contains(ind.value)) {
                val pos = positions(hayLower, ind)
                if (pos.isNotEmpty()) found.add(ind to pos)
            }
        }
        // Prune a parent whose every occurrence is the tail of a matched child.
        val keep = ArrayList<Indicator>()
        for ((ind, occ) in found) {
            if (ind.type != "domain") { keep.add(ind); continue }
            val children = found.map { it.first.value }
                .filter { it != ind.value && it.endsWith("." + ind.value) }
            if (children.isEmpty()) { keep.add(ind); continue }
            val standalone = occ.any { p ->
                children.none { child ->
                    val extra = child.length - ind.value.length
                    p - extra >= 0 && hayLower.substring(p - extra, p + ind.value.length) == child
                }
            }
            if (standalone) keep.add(ind)
        }
        return keep
    }

    /** Most specific indicator for one hostname (exact or parent-domain match), or null. */
    fun matchHostname(hostRaw: String): Indicator? {
        val host = hostRaw.trim().lowercase().trimEnd('.')
        var best: Indicator? = null
        for (ind in domains) {
            if (host == ind.value || host.endsWith("." + ind.value)) {
                if (best == null || ind.value.length > best.value.length) best = ind
            }
        }
        return best
    }

    companion object {
        private val shaRe = Regex("^[0-9a-f]{64}$")
        private val ipv4Re = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        private val asOfRe = Regex("^#\\s*as-of:\\s*(\\d{4}-\\d{2}-\\d{2})\\s*$")

        fun inferType(v: String): String = when {
            shaRe.matches(v) -> "sha256"
            ipv4Re.matches(v) || (v.contains(':') && v.all { it in "0123456789abcdef:" }) -> "ip"
            else -> "domain"
        }

        fun load(input: InputStream): IocSet {
            var asOf: String? = null
            val seen = LinkedHashMap<String, Indicator>()
            input.bufferedReader(Charsets.UTF_8).useLines { lines ->
                for (raw in lines) {
                    val line = raw.trim().trimStart('\uFEFF')
                    if (line.isEmpty() || line.startsWith("#")) {
                        asOfRe.matchEntire(line)?.let { asOf = it.groupValues[1] }
                        continue
                    }
                    val parts = line.split('\t').map { it.trim() }.filter { it.isNotEmpty() }
                    if (parts.size < 3) continue
                    val value = parts[0].lowercase()
                    seen[value] = Indicator(
                        value = value,
                        tier = parts[1],
                        confidence = parts[2],
                        source = if (parts.size > 3) parts[3] else "",
                        type = inferType(value)
                    )
                }
            }
            return IocSet(seen.values.sortedBy { it.value }, asOf)
        }
    }
}
