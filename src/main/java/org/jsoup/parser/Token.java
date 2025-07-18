package org.jsoup.parser;

import org.jsoup.helper.Validate;
import org.jsoup.internal.Normalizer;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Range;
import org.jspecify.annotations.Nullable;

/**
 * Parse tokens for the Tokeniser.
 */
public abstract class Token {
    static  int UnsetPos = -1;
     TokenType type; // used in switches in TreeBuilder vs .getClass()
    int startPos, endPos = UnsetPos; // position in CharacterReader this token was read from

    public Token(TokenType type) {
        this.type = type;
    }
    
    String tokenType() {
        return this.getClass().getSimpleName();
    }

    /**
     * Reset the data represent by this token, for reuse. Prevents the need to create transfer objects for every
     * piece of data, which immediately get GCed.
     */
    Token reset() {
        startPos = UnsetPos;
        endPos = UnsetPos;
        return this;
    }

    int startPos() {
        return startPos;
    }

    void startPos(int pos) {
        startPos = pos;
    }

    int endPos() {
        return endPos;
    }

    void endPos(int pos) {
        endPos = pos;
    }

    static  class Doctype extends Token {
         TokenData name = new TokenData();
        @Nullable String pubSysKey = null;
         TokenData publicIdentifier = new TokenData();
         TokenData systemIdentifier = new TokenData();
        boolean forceQuirks = false;

        Doctype() {
            super(TokenType.Doctype);
        }

        @Override
        Token reset() {
            super.reset();
            name.reset();
            pubSysKey = null;
            publicIdentifier.reset();
            systemIdentifier.reset();
            forceQuirks = false;
            return this;
        }

        String getName() {
            return name.value();
        }

        @Nullable String getPubSysKey() {
            return pubSysKey;
        }

        String getPublicIdentifier() {
            return publicIdentifier.value();
        }

        public String getSystemIdentifier() {
            return systemIdentifier.value();
        }

        public boolean isForceQuirks() {
            return forceQuirks;
        }

        @Override
        public String toString() {
            return "<!doctype " + getName() + ">";
        }
    }

    static abstract class Tag extends Token {
        protected TokenData tagName = new TokenData();
        @Nullable protected String normalName; // lc version of tag name, for case-insensitive tree build
        boolean selfClosing = false;
        @Nullable Attributes attributes; // start tags get attributes on construction. End tags get attributes on first new attribute (but only for parser convenience, not used).

         private TokenData attrName = new TokenData();
         private TokenData attrValue = new TokenData();
        private boolean hasEmptyAttrValue = false; // distinguish boolean attribute from empty string value

        // attribute source range tracking
         TreeBuilder treeBuilder;
         boolean trackSource;
        int attrNameStart, attrNameEnd, attrValStart, attrValEnd;

        Tag(TokenType type, TreeBuilder treeBuilder) {
            super(type);
            this.treeBuilder = treeBuilder;
            this.trackSource = treeBuilder.trackSourceRange;
        }

        @Override
        Tag reset() {
            super.reset();
            tagName.reset();
            normalName = null;
            selfClosing = false;
            attributes = null;
            resetPendingAttr();
            return this;
        }

        private void resetPendingAttr() {
            attrName.reset();
            attrValue.reset();
            hasEmptyAttrValue = false;

            if (trackSource)
                attrNameStart = attrNameEnd = attrValStart = attrValEnd = UnsetPos;
        }

        /* Limits runaway crafted HTML from spewing attributes and getting a little sluggish in ensureCapacity.
        Real-world HTML will P99 around 8 attributes, so plenty of headroom. Implemented here and not in the Attributes
        object so that API users can add more if ever required. */
        private static  int MaxAttributes = 512;

         void newAttribute() {
            if (attributes == null)
                attributes = new Attributes();

            if (attrName.hasData() && attributes.size() < MaxAttributes) {
                // the tokeniser has skipped whitespace control chars, but trimming could collapse to empty for other control codes, so verify here
                String name = attrName.value();
                name = name.trim();
                if (!name.isEmpty()) {
                    String value;
                    if (attrValue.hasData())
                        value = attrValue.value();
                    else if (hasEmptyAttrValue)
                        value = "";
                    else
                        value = null;
                    // note that we add, not put. So that the first is kept, and rest are deduped, once in a context where case sensitivity is known, and we can warn for duplicates.
                    attributes.add(name, value);

                    trackAttributeRange(name);
                }
            }
            resetPendingAttr();
        }

        private void trackAttributeRange(String name) {
            if (trackSource && isStartTag()) {
                 StartTag start = asStartTag();
                 CharacterReader r = start.treeBuilder.reader;
                 boolean preserve = start.treeBuilder.settings.preserveAttributeCase();

                assert attributes != null;
                if (!preserve) name = Normalizer.lowerCase(name);
                if (attributes.sourceRange(name).nameRange().isTracked()) return; // dedupe ranges as we go; actual attributes get deduped later for error count

                // if there's no value (e.g. boolean), make it an implicit range at current
                if (!attrValue.hasData()) attrValStart = attrValEnd = attrNameEnd;

                Range.AttributeRange range = new Range.AttributeRange(
                    new Range(
                        new Range.Position(attrNameStart, r.lineNumber(attrNameStart), r.columnNumber(attrNameStart)),
                        new Range.Position(attrNameEnd, r.lineNumber(attrNameEnd), r.columnNumber(attrNameEnd))),
                    new Range(
                        new Range.Position(attrValStart, r.lineNumber(attrValStart), r.columnNumber(attrValStart)),
                        new Range.Position(attrValEnd, r.lineNumber(attrValEnd), r.columnNumber(attrValEnd)))
                );
                attributes.sourceRange(name, range);
            }
        }

         boolean hasAttributes() {
            return attributes != null;
        }

         boolean hasAttributeIgnoreCase(String key) {
            return attributes != null && attributes.hasKeyIgnoreCase(key);
        }

         void iseTag() {
            // ises for emit
            if (attrName.hasData()) {
                newAttribute();
            }
        }

        /** Preserves case */
         String name() { // preserves case, for input into Tag.valueOf (which may drop case)
            return tagName.value();
        }

        /** Lower case */
         String normalName() { // lower case, used in tree building for working out where in tree it should go
            Validate.isFalse(normalName == null || normalName.isEmpty());
            return normalName;
        }

         String toStringName() {
            String name = tagName.value();
            return (name.isEmpty()) ? "[unset]" : name;
        }

         Tag name(String name) {
            tagName.set(name);
            normalName = ParseSettings.normalName(tagName.value());
            return this;
        }

         boolean isSelfClosing() {
            return selfClosing;
        }

        // these appenders are rarely hit in not null state-- caused by null chars.
         void appendTagName(String append) {
            // might have null chars - need to replace with null replacement character
            append = append.replace(TokeniserState.nullChar, Tokeniser.replacementChar);
            tagName.append(append);
            normalName = ParseSettings.normalName(tagName.value());
        }

         void appendTagName(char append) {
            appendTagName(String.valueOf(append)); // so that normalname gets updated too
        }

         void appendAttributeName(String append, int startPos, int endPos) {
            // might have null chars because we eat in one pass - need to replace with null replacement character
            append = append.replace(TokeniserState.nullChar, Tokeniser.replacementChar);
            attrName.append(append);
            attrNamePos(startPos, endPos);
        }

         void appendAttributeName(char append, int startPos, int endPos) {
            attrName.append(append);
            attrNamePos(startPos, endPos);
        }

         void appendAttributeValue(String append, int startPos, int endPos) {
            attrValue.append(append);
            attrValPos(startPos, endPos);
        }

         void appendAttributeValue(char append, int startPos, int endPos) {
            attrValue.append(append);
            attrValPos(startPos, endPos);
        }

         void appendAttributeValue(int[] appendCodepoints, int startPos, int endPos) {
            for (int codepoint : appendCodepoints) {
                attrValue.appendCodePoint(codepoint);
            }
            attrValPos(startPos, endPos);
        }
        
         void setEmptyAttributeValue() {
            hasEmptyAttrValue = true;
        }

        private void attrNamePos(int startPos, int endPos) {
            if (trackSource) {
                attrNameStart = attrNameStart > UnsetPos ? attrNameStart : startPos; // latches to first
                attrNameEnd = endPos;
            }
        }

        private void attrValPos(int startPos, int endPos) {
            if (trackSource) {
                attrValStart = attrValStart > UnsetPos ? attrValStart : startPos; // latches to first
                attrValEnd = endPos;
            }
        }

        @Override
        abstract public String toString();
    }

     static class StartTag extends Tag {

        // TreeBuilder is provided so if tracking, can get line / column positions for Range; and can dedupe as we go
        StartTag(TreeBuilder treeBuilder) {
            super(TokenType.StartTag, treeBuilder);
        }

        @Override
        Tag reset() {
            super.reset();
            attributes = null;
            return this;
        }

        StartTag nameAttr(String name, Attributes attributes) {
            this.tagName.set(name);
            this.attributes = attributes;
            normalName = ParseSettings.normalName(name);
            return this;
        }

        @Override
        public String toString() {
            String closer = isSelfClosing() ? "/>" : ">";
            if (hasAttributes() && attributes.size() > 0)
                return "<" + toStringName() + " " + attributes.toString() + closer;
            else
                return "<" + toStringName() + closer;
        }
    }

     static class EndTag extends Tag{
        EndTag(TreeBuilder treeBuilder) {
            super(TokenType.EndTag, treeBuilder);
        }

        @Override
        public String toString() {
            return "</" + toStringName() + ">";
        }
    }

     static class Comment extends Token {
        private  TokenData data = new TokenData();
        boolean bogus = false;

        @Override
        Token reset() {
            super.reset();
            data.reset();
            bogus = false;
            return this;
        }

        Comment() {
            super(TokenType.Comment);
        }

        String getData() {
            return data.value();
        }

        Comment append(String append) {
            data.append(append);
            return this;
        }

        Comment append(char append) {
            data.append(append);
            return this;
        }

        @Override
        public String toString() {
            return "<!--" + getData() + "-->";
        }
    }

    static class Character extends Token {
         TokenData data = new TokenData();

        Character() {
            super(TokenType.Character);
        }

        /** Deep copy */
        Character(Character source) {
            super(TokenType.Character);
            this.startPos = source.startPos;
            this.endPos = source.endPos;
            this.data.set(source.data.value());
        }

        @Override
        Token reset() {
            super.reset();
            data.reset();
            return this;
        }

        Character data(String str) {
            data.set(str);
            return this;
        }

        Character append(String str) {
            data.append(str);
            return this;
        }

        String getData() {
            return data.value();
        }

        @Override
        public String toString() {
            return getData();
        }

    }

     static class CData extends Character {
        CData(String data) {
            super();
            this.data(data);
        }

        @Override
        public String toString() {
            return "<![CDATA[" + getData() + "]]>";
        }

    }

    /**
     XmlDeclaration - extends Tag for pseudo attribute support
     */
     static class XmlDecl extends Tag {
        boolean isDeclaration = true; // <!..>, or <?...?> if false (a processing instruction)

        public XmlDecl(TreeBuilder treeBuilder) {
            super(TokenType.XmlDecl, treeBuilder);
        }

        @Override
        XmlDecl reset() {
            super.reset();
            isDeclaration = true;
            return this;
        }

        @Override
        public String toString() {
            String open = isDeclaration ? "<!" : "<?";
            String close = isDeclaration ? ">" : "?>";
            if (hasAttributes() && attributes.size() > 0)
                return open + toStringName() + " " + attributes.toString() + close;
            else
                return open + toStringName() + close;
        }
    }

     static class EOF extends Token {
        EOF() {
            super(Token.TokenType.EOF);
        }

        @Override
        Token reset() {
            super.reset();
            return this;
        }

        @Override
        public String toString() {
            return "";
        }
    }

     boolean isDoctype() {
        return type == TokenType.Doctype;
    }

     Doctype asDoctype() {
        return (Doctype) this;
    }

     boolean isStartTag() {
        return type == TokenType.StartTag;
    }

     StartTag asStartTag() {
        return (StartTag) this;
    }

     boolean isEndTag() {
        return type == TokenType.EndTag;
    }

     EndTag asEndTag() {
        return (EndTag) this;
    }

     boolean isComment() {
        return type == TokenType.Comment;
    }

     Comment asComment() {
        return (Comment) this;
    }

     boolean isCharacter() {
        return type == TokenType.Character;
    }

     boolean isCData() {
        return this instanceof CData;
    }

     Character asCharacter() {
        return (Character) this;
    }

     XmlDecl asXmlDecl() {
        return (XmlDecl) this;
    }

     boolean isEOF() {
        return type == TokenType.EOF;
    }

    public enum TokenType {
        Doctype,
        StartTag,
        EndTag,
        Comment,
        Character, // note no CData - treated in builder as an extension of Character
        XmlDecl,
        EOF
    }
}
