package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.parser.parseToEnd
import com.tyro.techtalk.parsingfancy.threatmodel.Target
import io.kotlintest.TestCaseConfig
import io.kotlintest.matchers.contain
import io.kotlintest.matchers.containsInOrder
import io.kotlintest.matchers.should
import io.kotlintest.specs.FreeSpec

class ThreatModelParserTest : FreeSpec() {
    private val tokenizer = ThreatModelParser.tokenizer
    private val targetFragment =
            """Targets:
               |    Tyro is defended by jost.
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

        "The threat section parser should" - {
            "parse threats" {
                val targets = ThreatModelParser.targetSection.parseToEnd(tokenizer.tokenize(targetFragment))

                targets should contain(Target("Tyro", "jost"))
            }
        }
    }

    override val defaultTestCaseConfig: TestCaseConfig
        get() = super.defaultTestCaseConfig
}