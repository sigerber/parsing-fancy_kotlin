package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.grammar.Grammar
import com.github.h0tk3y.betterParse.parser.Parser
import com.tyro.techtalk.parsingfancy.threatmodel.*
import com.tyro.techtalk.parsingfancy.threatmodel.Target

object ThreatModelParser : Grammar<List<AttackResult>>() {
    private val TARGET_HEADER by token("Targets:")
    private val THREAT_HEADER by token("Threats:")
    private val SCENARIO_HEADER by token("Scenarios:")

    private val COMMA by token(",")
    private val LBRACE by token("\\[")
    private val RBRACE by token("]")

    private val VERSUS by token("vs")

    private val NO_DEFENCES by token("is undefended")
    private val DEFENSES_PREFIX by token("is defended by")

    private val NO_WEAKNESSES by token("has no weaknesses")
    private val WEAKNESSES_SINGULAR by token("is weak against")

    private val IDENT by token("\\w+")

    private val WHITESPACE by token("\\s+", ignore = true)

    val identifierList: Parser<List<String>> = todo()

    val targetSection: Parser<List<Target>> = todo()

    val threatSection: Parser<List<Threat>> = todo()

    val scenarioSection: Parser<List<Pair<String, String>>> = todo()

    override val rootParser: Parser<List<AttackResult>> by todo()
}

