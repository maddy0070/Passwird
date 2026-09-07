package com.passwird.vault.generator

import java.math.BigInteger
import kotlin.math.ln

/**
 * Counting arguments shared by the generator and the strength estimator.
 *
 * Both need the same question answered — *how many strings of this length use every one of
 * these character classes?* — and they must answer it identically, or the app would print
 * one number when it generates a password and a different one when it later re-reads it.
 */
object EntropyMath {

    private val LN2 = ln(2.0)

    fun log2(value: Double): Double = ln(value) / LN2

    /** Exact for arbitrarily large counts, where `toDouble()` would overflow to infinity. */
    fun log2(value: BigInteger): Double {
        val bitLength = value.bitLength()
        if (bitLength <= 62) return log2(value.toDouble())
        val shift = bitLength - 62
        return log2(value.shiftRight(shift).toDouble()) + shift
    }

    /**
     * Strings of [length] over classes of the given [classSizes] that use **every** class.
     *
     * Inclusion–exclusion over which classes are absent:
     * ```
     * Σ over subsets S  (-1)^|S| · (N − Σ_{i∈S} nᵢ)^length
     * ```
     */
    fun countUsingEveryClass(classSizes: List<Int>, length: Int): BigInteger {
        val total = classSizes.sum()
        var count = BigInteger.ZERO

        for (mask in 0 until (1 shl classSizes.size)) {
            var excluded = 0
            var bitsSet = 0
            for (i in classSizes.indices) {
                if ((mask shr i) and 1 == 1) {
                    excluded += classSizes[i]
                    bitsSet++
                }
            }
            val term = BigInteger.valueOf((total - excluded).toLong()).pow(length)
            count = if (bitsSet % 2 == 0) count.add(term) else count.subtract(term)
        }
        return count
    }

    /** Entropy of a uniform draw from [countUsingEveryClass]. */
    fun bitsUsingEveryClass(classSizes: List<Int>, length: Int): Double {
        val count = countUsingEveryClass(classSizes, length)
        return if (count.signum() <= 0) 0.0 else log2(count)
    }
}
