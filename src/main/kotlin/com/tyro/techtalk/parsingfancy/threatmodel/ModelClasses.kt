package com.tyro.techtalk.parsingfancy.threatmodel

data class CounterMeasure constructor(val name: String)

data class Target(val name: String, val defendedBy: Set<CounterMeasure>) {
    constructor(name: String, vararg defendedBy: String) : this(name, defendedBy.map { CounterMeasure(it) }.toSet())
}

data class Threat(val name: String, val counteredBy: Set<CounterMeasure>) {
    constructor(name: String, vararg counteredBy: String) : this(name, counteredBy.map { CounterMeasure(it) }.toSet())
}