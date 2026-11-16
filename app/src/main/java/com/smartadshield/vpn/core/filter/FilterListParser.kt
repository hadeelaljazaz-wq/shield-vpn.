package com.smartadshield.vpn.core.filter

import java.io.BufferedReader
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Parses filter lists, keeping only rules whose semantics can be honoured at DNS level:
 *
 *  - hosts files:        `0.0.0.0 ads.example.com` / `127.0.0.1 ...` / `:: ...`
 *  - plain domain lists: `ads.example.com`
 *  - adblock/AdGuard:    `||ads.example.com^`, `||ads.example.com^$important`,
 *                        `@@||cdn.example.com^` (exception), `||mon*.example.com^` (wildcard)
 *
 * Everything else (cosmetic `##` rules, URL paths, regex, `$third-party`, `$domain=`, `$client`,
 * `$dnsrewrite`, `$badfilter`, IP-address rules …) is counted as skipped: those rules need a
 * browser/HTTP context, and applying them at DNS level would over-block.
 */
object FilterListParser {

    class Result(
        val block: DomainHashSet,
        val allow: DomainHashSet,
        val wildcardBlock: WildcardRules,
        val wildcardAllow: WildcardRules,
        val totalLines: Int,
        val ruleLines: Int,
        val accepted: Int,
        val skipped: Int,
        val looksLikeHtml: Boolean,
        /** Sample of accepted blocked domains (for conflict checks); capped. */
        val blockedDomainsSample: List<String>,
    ) {
        val ruleCount: Int get() = block.size + allow.size + wildcardBlock.size + wildcardAllow.size
    }

    private val HOSTS_IPS = setOf("0.0.0.0", "127.0.0.1", "::", "::1", "::0", "0", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1")
    private val IGNORED_HOSTS = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
        "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
        "ip6-allhosts", "0.0.0.0",
    )

    fun isValidHostname(h: String, allowWildcard: Boolean = false): Boolean {
        if (h.isEmpty() || h.length > 253 || h.startsWith('.') || h.endsWith('.') || h.startsWith('-')) return false
        var labelLen = 0
        var hasLetter = false
        for (c in h) {
            when {
                c == '.' -> { if (labelLen == 0) return false; labelLen = 0 }
                c in 'a'..'z' || c == '-' || c == '_' -> { labelLen++; hasLetter = true }
                c in '0'..'9' -> labelLen++
                c == '*' && allowWildcard -> labelLen++
                else -> return false
            }
            if (labelLen > 63) return false
        }
        // Pure IP literals (e.g. ||1.2.3.4^) are useless for DNS filtering.
        return hasLetter && h.contains('.')
    }

    private sealed interface Rule
    private class Block(val host: String) : Rule
    private class Allow(val host: String) : Rule

    private fun parseLine(raw: String): Rule? {
        var line = raw.trim()
        if (line.isEmpty()) return null
        val c0 = line[0]
        if (c0 == '!' || c0 == '[' || c0 == '#') return null
        if (line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") || line.contains("#%#")) return null

        // hosts format
        val ws = line.indexOfFirst { it == ' ' || it == '\t' }
        if (ws > 0) {
            val ip = line.substring(0, ws)
            if (ip in HOSTS_IPS) {
                var rest = line.substring(ws).trim()
                val hash = rest.indexOf('#')
                if (hash >= 0) rest = rest.substring(0, hash).trim()
                val host = rest.split(' ', '\t').firstOrNull()?.lowercase() ?: return null
                if (host in IGNORED_HOSTS || !isValidHostname(host)) return null
                return Block(host)
            }
            return null
        }

        var exception = false
        if (line.startsWith("@@")) { exception = true; line = line.substring(2) }

        if (line.startsWith("||")) {
            var body = line.substring(2)
            var modifiers = ""
            val dollar = body.indexOf('$')
            if (dollar >= 0) { modifiers = body.substring(dollar + 1); body = body.substring(0, dollar) }
            if (modifiers.isNotEmpty() && modifiers.split(',').any { it.trim() != "important" }) return null
            if (body.endsWith("^")) body = body.dropLast(1)
            else if (body.endsWith("^|")) body = body.dropLast(2)
            if (body.endsWith(".")) return null // prefix rule like ||rgfftupf.
            if (body.startsWith("*.")) body = body.substring(2)
            body = body.lowercase()
            if (!isValidHostname(body, allowWildcard = true)) return null
            if (body.startsWith('*') || body.endsWith('*') && !body.contains('.')) return null
            return if (exception) Allow(body) else Block(body)
        }
        if (exception) return null

        // plain domain list
        val host = line.lowercase()
        if (isValidHostname(host)) return Block(host)
        return null
    }

    fun parse(reader: BufferedReader, sampleCap: Int = 0): Result {
        val block = DomainHashSet.Builder(1 shl 16)
        val allow = DomainHashSet.Builder(256)
        val wb = ArrayList<String>()
        val wa = ArrayList<String>()
        val sample = ArrayList<String>()
        var total = 0
        var ruleLines = 0
        var accepted = 0
        var html = false
        while (true) {
            val line = reader.readLine() ?: break
            total++
            if (total <= 5) {
                val l = line.trimStart().lowercase()
                if (l.startsWith("<!doctype") || l.startsWith("<html")) html = true
            }
            val t = line.trim()
            if (t.isEmpty() || t[0] == '!' || t[0] == '#' || t[0] == '[') continue
            ruleLines++
            when (val r = parseLine(t)) {
                is Block -> {
                    accepted++
                    if (r.host.contains('*')) wb.add(r.host) else {
                        block.add(r.host)
                        if (sample.size < sampleCap) sample.add(r.host)
                    }
                }
                is Allow -> {
                    accepted++
                    if (r.host.contains('*')) wa.add(r.host) else allow.add(r.host)
                }
                null -> {}
            }
        }
        return Result(
            block.build(), allow.build(), WildcardRules(wb.distinct()), WildcardRules(wa.distinct()),
            total, ruleLines, accepted, ruleLines - accepted, html, sample,
        )
    }

    /** Parses a simple curated list (one domain per line, `#` comments). */
    fun parseDomains(lines: Sequence<String>): List<String> = lines
        .map { it.substringBefore('#').trim().lowercase() }
        .filter { isValidHostname(it) }
        .toList()
}

/** Compiled, validated representation of one remote list, persisted as a binary file. */
class CompiledList(
    val block: DomainHashSet,
    val allow: DomainHashSet,
    val wildcardBlock: WildcardRules,
    val wildcardAllow: WildcardRules,
) {
    val ruleCount: Int get() = block.size + allow.size + wildcardBlock.size + wildcardAllow.size

    fun write(out: DataOutputStream) {
        out.writeInt(MAGIC)
        out.writeInt(VERSION)
        block.write(out)
        allow.write(out)
        out.writeInt(wildcardBlock.patterns.size); wildcardBlock.patterns.forEach(out::writeUTF)
        out.writeInt(wildcardAllow.patterns.size); wildcardAllow.patterns.forEach(out::writeUTF)
    }

    companion object {
        private const val MAGIC = 0x53415348 // "SASH"
        private const val VERSION = 1

        fun from(r: FilterListParser.Result) = CompiledList(r.block, r.allow, r.wildcardBlock, r.wildcardAllow)

        fun read(input: DataInputStream): CompiledList {
            require(input.readInt() == MAGIC) { "bad magic" }
            require(input.readInt() == VERSION) { "bad version" }
            val b = DomainHashSet.read(input)
            val a = DomainHashSet.read(input)
            val nb = input.readInt(); require(nb in 0..100_000)
            val wb = List(nb) { input.readUTF() }
            val na = input.readInt(); require(na in 0..100_000)
            val wa = List(na) { input.readUTF() }
            return CompiledList(b, a, WildcardRules(wb), WildcardRules(wa))
        }
    }
}
