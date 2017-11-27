package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.grammar.tryParseToEnd
import com.github.h0tk3y.betterParse.parser.ErrorResult
import com.github.h0tk3y.betterParse.parser.Parsed
import com.github.h0tk3y.betterParse.parser.tryParseToEnd
import com.tyro.techtalk.parsingfancy.threatmodel.Compromised
import com.tyro.techtalk.parsingfancy.threatmodel.Target
import com.tyro.techtalk.parsingfancy.threatmodel.Threat
import com.tyro.techtalk.parsingfancy.threatmodel.UnCompromised
import io.kotlintest.matchers.*
import org.junit.Test

class ThreatModelParserTest {
    private val tokenizer = ThreatModelParser.tokenizer
    private val targetFragment =
            """Targets:
               |    ??? is undefended
               |    ??? is defended by ???
               |    ??? is defended by [???, ???]
            """.trimMargin()

    private val threatFragment =
            """Threats:
               |    ??? has no weaknesses
               |    ??? is weak against ???
               |    ??? is weak against [???, ???]
               """.trimMargin()

    private val scenarioFragment =
            """Scenarios:
               | ??? vs ???
               | ??? vs ???
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
        val result = ThreatModelParser.identifierList.tryParseToEnd(tokenizer.tokenize("[abc, def]"))

        when (result) {
            is Parsed -> {
                result.value should containsInOrder("abc", "def")
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }
    }

    @Test
    fun `the identifier parser should parse a single identifier as a list`() {
        val result = ThreatModelParser.identifierList.tryParseToEnd(tokenizer.tokenize("abc"))

        when (result) {
            is Parsed -> {
                result.value should contain("abc")
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }
    }

    @Test
    fun `the target parser should parse a whitespace separated list of targets`() {
        val result = ThreatModelParser.targetSection.tryParseToEnd(tokenizer.tokenize(targetFragment))

        when (result) {
            is Parsed -> {
                val targets = result.value

                targets should contain(Target("TheVault"))
                targets should contain(Target("Tyro", "jost", "obscurity"))
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }
    }

    @Test
    fun `the threat parser should parse a whitespace separated list of threats`() {
        val result = ThreatModelParser.threatSection.tryParseToEnd(tokenizer.tokenize(threatFragment))

        when (result) {
            is Parsed -> {
                val threats = result.value

                threats should contain(Threat("Hackers", "obscurity"))
                threats should contain(Threat("GlobalWarming"))
                threats should contain(Threat("Kotlin", "Scala", "Haskell"))
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }
    }

    @Test
    fun `the scenario parser should parse a whitespace separated list of scenarios`() {
        val result = ThreatModelParser.scenarioSection.tryParseToEnd(tokenizer.tokenize(scenarioFragment))

        when (result) {
            is Parsed -> {
                val scenarios = result.value
                scenarios should contain(Pair("Hackers", "Tyro"))
                scenarios should contain(Pair("GlobalWarming", "Tyro"))
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }
    }

    @Test
    fun `the threat model grammar should parse and evaluate threat scenarios`() {
        val result = ThreatModelParser.tryParseToEnd(entireDSL)

        when (result) {
            is Parsed -> {
                result.value[0] shouldBe UnCompromised
                result.value[1] shouldBe Compromised
            }
            is ErrorResult -> {
                fail("Could not parse threat scenarios: $result")
            }
        }

    }
}