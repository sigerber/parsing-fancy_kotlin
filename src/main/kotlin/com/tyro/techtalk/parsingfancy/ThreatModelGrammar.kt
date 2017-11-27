package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.combinators.*
import com.github.h0tk3y.betterParse.grammar.Grammar
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
    private val WEAKNESSES_PLURAL by token("are weak against")

    private val IDENT by token("\\w+")

    private val WHITESPACE by token("\\s+", ignore = true)

    val oneIdentifier = IDENT use { listOf(text) }
    private val manyIdentifiers = (skip(LBRACE) and separatedTerms(IDENT, COMMA) and skip(RBRACE)) map { it.map { it.text } }
    val identifierList = oneIdentifier or manyIdentifiers

    private val noDefenses = NO_DEFENCES asJust emptyList<CounterMeasure>()
    private val someDefenses = (skip(DEFENSES_PREFIX) and identifierList) map { it.map(::CounterMeasure) }
    private val defences = noDefenses or someDefenses

    private val target = IDENT and defences use { Target(t1.text, t2.toSet()) }
    private val targets = separatedTerms(target, WHITESPACE)
    val targetSection = skip(TARGET_HEADER) and targets

    private val noWeaknesses = NO_WEAKNESSES asJust emptyList<CounterMeasure>()
    private val someWeaknesses = skip(WEAKNESSES_PLURAL or WEAKNESSES_SINGULAR) and identifierList map { it.map(::CounterMeasure) }
    private val weaknesses = noWeaknesses or someWeaknesses

    private val threat = IDENT and weaknesses use { Threat(t1.text, t2.toSet()) }
    private val threats = separatedTerms(threat, WHITESPACE)
    val threatSection = skip(THREAT_HEADER) and threats

    private val scenario = IDENT and skip(VERSUS) and IDENT use { Pair(t1.text, t2.text) }
    private val scenarios = separatedTerms(scenario, WHITESPACE)
    val scenarioSection = skip(SCENARIO_HEADER) and scenarios

    override val rootParser by targetSection and threatSection and scenarioSection map { (targets, threats, scenarios) ->
        val targetMap = targets.map { it.name to it }.toMap()
        val threatMap = threats.map { it.name to it }.toMap()

        scenarios.map { (threatName, targetName) ->
            val target = targetMap.getOrDefault(targetName, Target(targetName))
            val threat = threatMap.getOrDefault(threatName, Threat(threatName))

            AttackScenario.modelAttack(target, threat)
        }
    }
}