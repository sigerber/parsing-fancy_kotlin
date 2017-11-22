package com.tyro.techtalk.parsingfancy.threatmodel

object AttackScenario {
    fun modelAttack(target: Target, threat: Threat): AttackResult {
        val validCounterMeasures = threat.counteredBy.intersect(target.defendedBy)
        return if (validCounterMeasures.isEmpty()) Compromised else UnCompromised
    }
}

sealed class AttackResult

object Compromised : AttackResult()

object UnCompromised : AttackResult()
