package org.jsoup.parser;

import org.jsoup.helper.Validate;
import org.jsoup.internal.StringUtil;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Entities;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;

/**
 * Readers the input stream into tokens.
 */
 public class Tokeniser {
    static  char replacementChar = '\uFFFD'; // replaces null character
    private static  char[] notCharRefCharsSorted = new char[]{'\t', '\n', '\r', '\f', ' ', '<', '&'};

    // Some illegal character escapes are parsed by browsers as windows-1252 instead. See issue #1034
    // https://html.spec.whatwg.org/multipage/parsing.html#numeric-character-reference-end-state
    static  int win1252ExtensionsStart = 0x80;
    static  int[] win1252Extensions = new int[] {
            // we could build this manually, but Windows-1252 is not a standard java charset so that could break on
            // some platforms - this table is verified with a test
            0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
            0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
            0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
            0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    };

    static {
        Arrays.sort(notCharRefCharsSorted);
    }

    private  CharacterReader reader; // html input
    private  ParseErrorList errors; // errors found while tokenising

    private TokeniserState state = TokeniserState.Data; // current tokenisation state
    @Nullable private Token emitPending = null; // the token we are about to emit on next read
    private boolean isEmitPending = false;
     TokenData dataBuffer = new TokenData(); // buffers data looking for </script>

     Document.OutputSettings.Syntax syntax; // html or xml syntax; affects processing of xml declarations vs as bogus comments
     Token.StartTag startPending;
     Token.EndTag endPending;
     Token.Tag tagPending; // tag we are building up: start or end pending
     Token.Character charPending = new Token.Character();
     Token.Doctype doctypePending = new Token.Doctype(); // doctype building up
     Token.Comment commentPending = new Token.Comment(); // comment building up
     Token.XmlDecl xmlDeclPending; // xml decl building up
    @Nullable private String lastStartTag; // the last start tag emitted, to test appropriate end tag
    @Nullable private String lastStartCloseSeq; // "</" + lastStartTag, so we can quickly check for that in RCData

    private int markupStartPos, charStartPos = 0; // reader pos at the start of markup / characters. markup updated on state transition, char on token emit.

    public Tokeniser(TreeBuilder treeBuilder) {
        syntax = treeBuilder instanceof XmlTreeBuilder ? Document.OutputSettings.Syntax.xml : Document.OutputSettings.Syntax.html;
        tagPending = startPending  = new Token.StartTag(treeBuilder);
        endPending = new Token.EndTag(treeBuilder);
        xmlDeclPending = new Token.XmlDecl(treeBuilder);
        this.reader = treeBuilder.reader;
        this.errors = treeBuilder.parser.getErrors();
    }

    Token read() {
        while (!isEmitPending) {
            state.read(this, reader);
        }

        // if emit is pending, a non-character token was found: return any chars in buffer, and leave token for next read:
        if (charPending.data.hasData()) {
            return charPending;
        } else {
            isEmitPending = false;
            assert emitPending != null;
            return emitPending;
        }
    }

    void emit(Token token) {
        Validate.isFalse(isEmitPending);

        emitPending = token;
        isEmitPending = true;
        token.startPos(markupStartPos);
        token.endPos(reader.pos());
        charStartPos = reader.pos(); // update char start when we complete a token emit

        if (token.type == Token.TokenType.StartTag) {
            Token.StartTag startTag = (Token.StartTag) token;
            lastStartTag = startTag.name();
            lastStartCloseSeq = null; // only lazy inits
        } else if (token.type == Token.TokenType.EndTag) {
            Token.EndTag endTag = (Token.EndTag) token;
            if (endTag.hasAttributes())
                error("Attributes incorrectly present on end tag [/%s]", endTag.normalName());
        }
    }

    void emit( String str) {
        // buffer strings up until last string token found, to emit only one token for a run of character refs etc.
        // does not set isEmitPending; read checks that
        // todo move "<" to '<'...
        charPending.append(str);
        charPending.startPos(charStartPos);
        charPending.endPos(reader.pos());
    }

    void emit(char c) {
        charPending.data.append(c);
        charPending.startPos(charStartPos);
        charPending.endPos(reader.pos());
    }

    void emit(int[] codepoints) {
        // todo review
        emit(new String(codepoints, 0, codepoints.length));
    }

    void transition(TokeniserState newState) {
        // track markup position on state transitions
        if (newState == TokeniserState.TagOpen)
            markupStartPos = reader.pos();

        this.state = newState;
    }

    void advanceTransition(TokeniserState newState) {
        transition(newState);
        reader.advance();
    }

     private int[] codepointHolder = new int[1]; // holder to not have to keep creating arrays
     private int[] multipointHolder = new int[2];

    /** Tries to consume a character reference, and returns: null if nothing, int[1], or int[2]. */
    int @Nullable [] consumeCharacterReference(@Nullable Character additionalAllowedCharacter, boolean inAttribute) {
        if (reader.isEmpty())
            return null;
        if (additionalAllowedCharacter != null && additionalAllowedCharacter == reader.current())
            return null;
        if (reader.matchesAnySorted(notCharRefCharsSorted))
            return null;

         int[] codeRef = codepointHolder;
        reader.mark();
        if (reader.matchConsume("#")) { // numbered
            boolean isHexMode = reader.matchConsumeIgnoreCase("X");
            String numRef = isHexMode ? reader.consumeHexSequence() : reader.consumeDigitSequence();
            if (numRef.isEmpty()) { // didn't match anything
                characterReferenceError("numeric reference with no numerals");
                reader.rewindToMark();
                return null;
            }

            reader.unmark();
            if (!reader.matchConsume(";"))
                characterReferenceError("missing semicolon on [&#%s]", numRef); // missing semi
            int charval = -1;
            try {
                int base = isHexMode ? 16 : 10;
                charval = Integer.valueOf(numRef, base);
            } catch (NumberFormatException ignored) {
                // skip
            }
            // todo: check for extra illegal unicode points as parse errors - described https://html.spec.whatwg.org/multipage/syntax.html#character-references and in Infra
            // The numeric character reference forms described above are allowed to reference any code point excluding U+000D CR, noncharacters, and controls other than ASCII whitespace.
            if (charval == -1 || charval > 0x10FFFF) {
                characterReferenceError("character [%s] outside of valid range", charval);
                codeRef[0] = replacementChar;
            } else {
                // fix illegal unicode characters to match browser behavior
                if (charval >= win1252ExtensionsStart && charval < win1252ExtensionsStart + win1252Extensions.length) {
                    characterReferenceError("character [%s] is not a valid unicode code point", charval);
                    charval = win1252Extensions[charval - win1252ExtensionsStart];
                }

                // todo: implement number replacement table
                // todo: check for extra illegal unicode points as parse errors
                codeRef[0] = charval;
            }
            return codeRef;
        } else { // named
            // get as many letters as possible, and look for matching entities.
            String nameRef = reader.consumeLetterThenDigitSequence();
            boolean looksLegit = reader.matches(';');
            // found if a base named entity without a ;, or an extended entity with the ;.
            boolean found = (Entities.isBaseNamedEntity(nameRef) || (Entities.isNamedEntity(nameRef) && looksLegit));

            if (!found) {
                reader.rewindToMark();
                if (looksLegit) // named with semicolon
                    characterReferenceError("invalid named reference [%s]", nameRef);
                if (inAttribute) return null;
                // check if there's a base prefix match; consume and use that if so
                String prefix = Entities.findPrefix(nameRef);
                if (prefix.isEmpty()) return null;
                reader.matchConsume(prefix);
                nameRef = prefix;
            }
            if (inAttribute && (reader.matchesAsciiAlpha() || reader.matchesDigit() || reader.matchesAny('=', '-', '_'))) {
                // don't want that to match
                reader.rewindToMark();
                return null;
            }

            reader.unmark();
            if (!reader.matchConsume(";"))
                characterReferenceError("missing semicolon on [&%s]", nameRef); // missing semi
            int numChars = Entities.codepointsForName(nameRef, multipointHolder);
            if (numChars == 1) {
                codeRef[0] = multipointHolder[0];
                return codeRef;
            } else if (numChars ==2) {
                return multipointHolder;
            } else {
                Validate.fail("Unexpected characters returned for " + nameRef);
                return multipointHolder;
            }
        }
    }

    Token.Tag createTagPending(boolean start) {
        tagPending = start ? startPending.reset() : endPending.reset();
        return tagPending;
    }

    Token.XmlDecl createXmlDeclPending(boolean isDeclaration) {
        Token.XmlDecl decl = xmlDeclPending.reset();
        decl.isDeclaration = isDeclaration;
        tagPending = decl;
        return decl;
    }

    void emitTagPending() {
        //tagPending.finaliseTag();
        emit(tagPending);
    }

    void createCommentPending() {
        commentPending.reset();
    }

    void emitCommentPending() {
        emit(commentPending);
    }

    void createBogusCommentPending() {
        commentPending.reset();
        commentPending.bogus = true;
    }

    void createDoctypePending() {
        doctypePending.reset();
    }

    void emitDoctypePending() {
        emit(doctypePending);
    }

    void createTempBuffer() {
        dataBuffer.reset();
    }

    boolean isAppropriateEndTagToken() {
        return lastStartTag != null && tagPending.name().equalsIgnoreCase(lastStartTag);
    }

    @Nullable String appropriateEndTagName() {
        return lastStartTag; // could be null
    }

    /** Returns the closer sequence {@code </lastStart} */
    String appropriateEndTagSeq() {
        if (lastStartCloseSeq == null) // reset on start tag emit
            lastStartCloseSeq = "</" + lastStartTag;
        return lastStartCloseSeq;
    }

    void error(TokeniserState state) {
        if (errors.canAddError())
            errors.add(new ParseError(reader, "Unexpected character '%s' in input state [%s]", reader.current(), state));
    }

    void eofError(TokeniserState state) {
        if (errors.canAddError())
            errors.add(new ParseError(reader, "Unexpectedly reached end of file (EOF) in input state [%s]", state));
    }

    private void characterReferenceError(String message, Object... args) {
        if (errors.canAddError())
            errors.add(new ParseError(reader, String.format("Invalid character reference: " + message, args)));
    }

    void error(String errorMsg) {
        if (errors.canAddError())
            errors.add(new ParseError(reader, errorMsg));
    }

    void error(String errorMsg, Object... args) {
        if (errors.canAddError())
            errors.add(new ParseError(reader, errorMsg, args));
    }

    /**
     * Utility method to consume reader and unescape entities found within.
     * @param inAttribute if the text to be unescaped is in an attribute
     * @return unescaped string from reader
     */
    String unescapeEntities(boolean inAttribute) {
        StringBuilder builder = StringUtil.borrowBuilder();
        while (!reader.isEmpty()) {
            builder.append(reader.consumeTo('&'));
            if (reader.matches('&')) {
                reader.consume();
                int[] c = consumeCharacterReference(null, inAttribute);
                if (c == null || c.length==0)
                    builder.append('&');
                else {
                    builder.appendCodePoint(c[0]);
                    if (c.length == 2)
                        builder.appendCodePoint(c[1]);
                }

            }
        }
        return StringUtil.releaseBuilder(builder);
    }
}
