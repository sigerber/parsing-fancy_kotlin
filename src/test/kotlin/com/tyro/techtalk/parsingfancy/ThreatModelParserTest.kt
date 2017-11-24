package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.grammar.parseToEnd
import com.github.h0tk3y.betterParse.parser.parseToEnd
import com.github.h0tk3y.betterParse.utils.Tuple2
import com.tyro.techtalk.parsingfancy.threatmodel.Compromised
import com.tyro.techtalk.parsingfancy.threatmodel.Target
import com.tyro.techtalk.parsingfancy.threatmodel.Threat
import com.tyro.techtalk.parsingfancy.threatmodel.UnCompromised
import io.kotlintest.TestCaseConfig
import io.kotlintest.matchers.contain
import io.kotlintest.matchers.containsInOrder
import io.kotlintest.matchers.should
import io.kotlintest.matchers.shouldBe
import io.kotlintest.specs.FreeSpec

class ThreatModelParserTest : FreeSpec() {
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


    init {
        "The identifier list parser" - {
            "parse an identifier with dashes and underscores" {
                val result = ThreatModelParser.oneIdentifier.parseToEnd(tokenizer.tokenize("abc-de_f"))

                result should contain("abc-de_f")
            }

            "parse a list of identifiers with spaces after the comma" {
                val results = ThreatModelParser.identifierList.parseToEnd(tokenizer.tokenize("[abc, def]"))

                results should containsInOrder("abc", "def")
            }

            "parse a list of identifiers without spaces after the comma" {
                val results = ThreatModelParser.identifierList.parseToEnd(tokenizer.tokenize("[abc,def]"))

                results should containsInOrder("abc", "def")
            }

            "parse a single identifier as a list" {
                val results = ThreatModelParser.identifierList.parseToEnd(tokenizer.tokenize("abc"))

                results should contain("abc")
            }
        }

        "The target section parser should" - {
            "parse targets" {
                val targets = ThreatModelParser.targetSection.parseToEnd(tokenizer.tokenize(targetFragment))

                targets should contain(Target("Tyro", "jost", "obscurity"))
                targets should contain(Target("TheVault"))
            }
        }

        "The threat parser should" - {
            "parse threats" {
                val threats = ThreatModelParser.threatSection.parseToEnd(tokenizer.tokenize(threatFragment))

                threats should contain(Threat("Hackers", "obscurity"))
                threats should contain(Threat("GlobalWarming"))
                threats should contain(Threat("Kotlin", "Scala", "Haskell"))
            }
        }

        "The scenario parser should" - {
            "parse scenarios" {
                val scenarios = ThreatModelParser.scenarioSection.parseToEnd(tokenizer.tokenize(scenarioFragment))

                scenarios should contain(Pair("Hackers", "Tyro"))
                scenarios should contain(Pair("GlobalWarming", "Tyro"))
            }
        }

        "The entire grammar should" - {
            "parse and evaluate attack scenarios" {
                val attackScenarios = ThreatModelParser.parseToEnd(entireDSL)

                attackScenarios[0] shouldBe UnCompromised
                attackScenarios[1] shouldBe Compromised
            }
        }
    }
}