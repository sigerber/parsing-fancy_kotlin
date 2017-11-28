package com.tyro.techtalk.parsingfancy

import com.github.h0tk3y.betterParse.lexer.TokenMatch
import com.github.h0tk3y.betterParse.parser.NoMatchingToken
import com.github.h0tk3y.betterParse.parser.ParseResult
import com.github.h0tk3y.betterParse.parser.Parser

fun <T> todo() = object : Parser<T> {
    override fun tryParse(tokens: Sequence<TokenMatch>): ParseResult<T> {
        return NoMatchingToken(tokens.first())
    }
}