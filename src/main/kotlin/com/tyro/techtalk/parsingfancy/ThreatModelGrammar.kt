package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.combinators.*
import com.github.h0tk3y.betterParse.grammar.Grammar
import com.tyro.techtalk.parsingfancy.threatmodel.CounterMeasure
import com.tyro.techtalk.parsingfancy.threatmodel.Target

object ThreatModelParser : Grammar<String>() {
    private val TARGET_HEADER by token("Targets: ")
    private val IDENT by token("[A-Za-z\\-_]+")
    private val COMMA by token(",\\s?")
    private val LBRACE by token("\\[")
    private val RBRACE by token("\\]")
    private val NO_DEFENCES by token("is undefended")
    private val DEFENSES_PREFIX by token("is defended by ")

    val oneIdentifier = IDENT use { listOf(text) }
    val manyIdentifiers = (skip(LBRACE) and separatedTerms(IDENT, COMMA) and skip(RBRACE)) map { it.map { it.text } }
    val identifierList = oneIdentifier or manyIdentifiers

    val noDefenses = NO_DEFENCES map { emptyList<String>() }
    val someDefenses = skip(DEFENSES_PREFIX) and identifierList
    val defences = (noDefenses or someDefenses) map { it.map { CounterMeasure(it) } }

    val target = IDENT and defences use { Target(t1.text, t2.toSet()) }
    val targetSection = skip(TARGET_HEADER) and target map { listOf(it) }

    override val rootParser = IDENT use { text }
}