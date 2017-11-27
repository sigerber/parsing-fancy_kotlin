package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.grammar.parseToEnd
import com.github.h0tk3y.betterParse.parser.parseToEnd
import com.tyro.techtalk.parsingfancy.threatmodel.Compromised
import com.tyro.techtalk.parsingfancy.threatmodel.Target
import com.tyro.techtalk.parsingfancy.threatmodel.Threat
import com.tyro.techtalk.parsingfancy.threatmodel.UnCompromised
import io.kotlintest.matchers.contain
import io.kotlintest.matchers.containsInOrder
import io.kotlintest.matchers.should
import io.kotlintest.matchers.shouldBe
import org.junit.Test

class ThreatModelParserTest {
    private val tokenizer = ThreatModelParser.tokenizer
    private val targetFragment =
            """Targets:
               |    Tyro is defended by [jost, obscurity]
               |    TheVault is undefended
            """.trimMargin()

    private val threatFragment =
            """Threats:
               |    Hackers are weak against obscurity
               |    GlobalWarming has no weaknesses
               |    Kotlin is weak against [Scala, Haskell]
               """.trimMargin()

    private val scenarioFragment =
            """Scenarios:
               | Hackers vs Tyro
               | GlobalWarming vs Tyro
               """.trimMargin()

    private val entireDSL =
            """$targetFragment
              |
              |$threatFragment
              |
              |$scenarioFragment
              """.trimMargin()


    @Test
    fun `the identifier parser should parse a command separated list of tokens`() {
        val results = ThreatModelParser.identifierList.parseToEnd(tokenizer.tokenize("[abc, def]"))

        results should containsInOrder("abc", "def")
    }

    @Test
    fun `the identifier parser should parse a single identifier as a list`() {
        val results = ThreatModelParser.identifierList.parseToEnd(tokenizer.tokenize("abc"))

        results should contain("abc")
    }

    @Test
    fun `the target parser should parse a whitespace separated list of targets`() {
        val targets = ThreatModelParser.targetSection.parseToEnd(tokenizer.tokenize(targetFragment))

        targets should contain(Target("TheVault"))
        targets should contain(Target("Tyro", "jost", "obscurity"))

    }

    @Test
    fun `the threat parser should parse a whitespace separated list of threats`() {
        val threats = ThreatModelParser.threatSection.parseToEnd(tokenizer.tokenize(threatFragment))

        threats should contain(Threat("Hackers", "obscurity"))
        threats should contain(Threat("GlobalWarming"))
        threats should contain(Threat("Kotlin", "Scala", "Haskell"))
    }

    @Test
    fun `the scenario parser should parse a whitespace separated list of scenarios`() {
        val scenarios = ThreatModelParser.scenarioSection.parseToEnd(tokenizer.tokenize(scenarioFragment))

        scenarios should contain(Pair("Hackers", "Tyro"))
        scenarios should contain(Pair("GlobalWarming", "Tyro"))
    }

    @Test
    fun `the threat model grammar should parse and evaluate threat scenarios`() {
        val attackScenarios = ThreatModelParser.parseToEnd(entireDSL)

        attackScenarios[0] shouldBe UnCompromised
        attackScenarios[1] shouldBe Compromised
    }
}