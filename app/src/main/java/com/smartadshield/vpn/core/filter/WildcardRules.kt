package com.smartadshield.vpn.core.filter

/**
 * Adblock-style host wildcard rules such as `||mon*.tiktokv.us^` or `||log*-normal-*.tiktokv.com`.
 * Only `*` is supported. A pattern matches a hostname if it matches the whole hostname or any
 * suffix that starts after a dot (the `||` anchor semantics).
 *
 * Rules are pre-filtered by their literal tail (text after the last `*`), so for typical lists
 * (a few hundred wildcard rules) a lookup costs a few hundred `endsWith` checks.
 */
class WildcardRules(val patterns: List<String>) {
    private val tails: Array<String> = patterns.map { it.substringAfterLast('*') }.toTypedArray()
    private val pats: Array<String> = patterns.toTypedArray()

    val size: Int get() = pats.size

    /** Returns the matching pattern or null. */
    fun match(domain: String): String? {
        for (i in pats.indices) {
            if (!domain.endsWith(tails[i])) continue
            val p = pats[i]
            var start = 0
            while (true) {
                if (glob(p, domain, start)) return p
                val dot = domain.indexOf('.', start)
                if (dot < 0) break
                start = dot + 1
            }
        }
        return null
    }

    companion object {
        val EMPTY = WildcardRules(emptyList())

        /** Iterative wildcard matcher ('*' = any sequence, including empty / dots). */
        fun glob(p: String, s: String, sStart: Int): Boolean {
            var pi = 0
            var si = sStart
            var starP = -1
            var starS = 0
            while (si < s.length) {
                if (pi < p.length && p[pi] != '*' && p[pi] == s[si]) {
                    pi++; si++
                } else if (pi < p.length && p[pi] == '*') {
                    starP = pi++; starS = si
                } else if (starP >= 0) {
                    pi = starP + 1; si = ++starS
                } else return false
            }
            while (pi < p.length && p[pi] == '*') pi++
            return pi == p.length
        }
    }
}
