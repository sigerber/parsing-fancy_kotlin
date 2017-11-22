package com.tyro.techtalk.parsingfancy.threatmodel

import io.kotlintest.properties.Gen
import io.kotlintest.properties.Gen.Companion.string
import io.kotlintest.properties.forAll
import io.kotlintest.specs.FreeSpec
import java.util.*

class AttackScenarioTest : FreeSpec() {
    init {
        "An attack scenario should" - {
            "result in a compromised target" - {
                "when the target has no defences" {
                    forAll(string(), threatGen) { name: String, threat: Threat ->
                        val target = Target(name, emptySet())
                        AttackScenario.modelAttack(target, threat) == Compromised
                    }
                }
            }

            "result in an un-compromised target" - {
                "when the target has a counter-defence" {
                    forAll(string(), threatGen) { name: String, threat: Threat ->
                        val target = Target(name, threat.counteredBy)

                        AttackScenario.modelAttack(target, threat) == UnCompromised
                    }
                }
            }
        }
    }

    private val counterMeasureGen = object : Gen<CounterMeasure> {
        override fun generate(): CounterMeasure = CounterMeasure(string().generate())
    }

    private val threatGen = object : Gen<Threat> {
        override fun generate(): Threat {
            val name = string().generate()
            return Threat(name, nonEmptySet(counterMeasureGen).generate())
        }
    }

    fun <T> nonEmptySet(gen: Gen<T>): Gen<Set<T>> = object : Gen<Set<T>> {
        override fun generate(): Set<T> = (1..RANDOM.nextInt(100) + 1).map { gen.generate() }.toSet()
    }

    private val RANDOM = Random()
}