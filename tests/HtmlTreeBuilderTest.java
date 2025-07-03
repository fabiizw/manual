package org.jsoup.parser;


import org.jsoup.Jsoup;
import org.jsoup.nodes.DataNode;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.Test;
import java.io.Reader;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

import static org.jsoup.parser.Parser.NamespaceHtml;
import static org.junit.jupiter.api.Assertions.*;

public class HtmlTreeBuilderTest {
    @Test
    public void ensureSearchArraysAreSorted() {
        List<Object[]> constants = HtmlTreeBuilderStateTest.findConstantArrays(HtmlTreeBuilder.class);
        HtmlTreeBuilderStateTest.ensureSorted(constants);
        assertEquals(14, constants.size());
    }

    @Test
    public void nonnull() {
        assertThrows(IllegalArgumentException.class, () -> {
                HtmlTreeBuilder treeBuilder = new HtmlTreeBuilder();
                treeBuilder.parse(null, null, null); // not sure how to test that these visual warnings actually appear! - test below checks for method annotation
            }
        ); // I'm not convinced that this lambda is easier to read than the old Junit 4 @Test(expected=IEA.class)...
    }

    @Test public void nonnullAssertions() throws NoSuchMethodException {
        Annotation[] declaredAnnotations = TreeBuilder.class.getPackage().getDeclaredAnnotations();
        boolean seen = false;
        for (Annotation annotation : declaredAnnotations) {
            if (annotation.annotationType().isAssignableFrom(NullMarked.class))
                seen = true;
        }

        // would need to rework this if/when that annotation moves from the method to the class / package.
        assertTrue(seen);
    }

    @Test void isSpecial() {
        ParseSettings settings = ParseSettings.htmlDefault;
        Element htmlEl = new Element(Tag.valueOf("div", NamespaceHtml, settings), "");
        assertTrue(HtmlTreeBuilder.isSpecial(htmlEl));

        Element notHtml = new Element(Tag.valueOf("not-html", NamespaceHtml, settings), "");
        assertFalse(HtmlTreeBuilder.isSpecial(notHtml));

        Element mathEl = new Element(Tag.valueOf("mi", Parser.NamespaceMathml, settings), "");
        assertTrue(HtmlTreeBuilder.isSpecial(mathEl));

        Element notMathEl = new Element(Tag.valueOf("not-math", Parser.NamespaceMathml, settings), "");
        assertFalse(HtmlTreeBuilder.isSpecial(notMathEl));

        Element svgEl = new Element(Tag.valueOf("title", Parser.NamespaceSvg, settings), "");
        assertTrue(HtmlTreeBuilder.isSpecial(svgEl));

        Element notSvgEl = new Element(Tag.valueOf("not-svg", Parser.NamespaceSvg, settings), "");
        assertFalse(HtmlTreeBuilder.isSpecial(notSvgEl));
    }

    @Test void customRcdataTag() {
        String inner = "Blah\nblah\n<foo>Foo</foo>\n&quot;";
        String innerText = "Blah\nblah\n<foo>Foo</foo>\n\"";
        String html = "<div><x>" + inner + "</x></div><div><x id=2></x></div>";
        TagSet custom = TagSet.Html();
        Tag x = custom.valueOf("x", NamespaceHtml);
        x.set(Tag.RcData);

        Document doc = Jsoup.parse(html, Parser.htmlParser().tagSet(custom));
        Element xEl = doc.expectFirst("x");
        assertEquals(x, xEl.tag());
        assertEquals(innerText, xEl.wholeText()); // <foo> is text no el

        // fragment parse context
        Element x2 = doc.expectFirst("#2");
        x2.html(inner); // <foo> will be text not el, via custom fragment context element
        assertEquals(innerText, x2.wholeText());
    }

    @Test void customDataTag() {
        String inner = "Blah\nblah\n<foo>Foo</foo>\n&quot;"; // no character refs, will be as-is
        String html = "<div><x>" + inner + "</x></div><div><x id=2></x></div>";
        TagSet custom = TagSet.Html();
        Tag x = custom.valueOf("x", NamespaceHtml);
        x.set(Tag.Data);

        Document doc = Jsoup.parse(html, Parser.htmlParser().tagSet(custom));
        Element xEl = doc.expectFirst("x");
        assertEquals(x, xEl.tag());
        assertEquals(inner, xEl.data());

        // fragment parse context
        Element x2 = doc.expectFirst("#2");
        x2.html(inner); // <foo> will be text not el, via custom fragment context element
        assertEquals(inner, xEl.data());
    }
}
