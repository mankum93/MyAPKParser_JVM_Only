/*
 * Copyright (c) 2015, Jared Rummler
 * Copyright (c) 2015, Liu Dong
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jaredrummler.apkparser.parser;

import com.jaredrummler.apkparser.struct.xml.Attribute;
import com.jaredrummler.apkparser.struct.xml.XmlCData;
import com.jaredrummler.apkparser.struct.xml.XmlNamespaceEndTag;
import com.jaredrummler.apkparser.struct.xml.XmlNamespaceStartTag;
import com.jaredrummler.apkparser.struct.xml.XmlNodeEndTag;
import com.jaredrummler.apkparser.struct.xml.XmlNodeStartTag;
import com.jaredrummler.apkparser.utils.xml.XmlEscaper;

import java.util.List;

public class XmlTranslator implements XmlStreamer {

  private StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
  private XmlNamespaces namespaces = new XmlNamespaces();
  private boolean isLastStartTag;
  private int shift;

  @Override public void onStartTag(XmlNodeStartTag xmlNodeStartTag) {
    if (isLastStartTag) {
      sb.append(">\n");
    }
    appendShift(shift++);
    sb.append('<');
    if (xmlNodeStartTag.getNamespace() != null) {
      String prefix = namespaces.getPrefixViaUri(xmlNodeStartTag.getNamespace());
      if (prefix != null) {
        sb.append(prefix).append(':');
      } else {
        sb.append(xmlNodeStartTag.getNamespace()).append(':');
      }
    }
    sb.append(xmlNodeStartTag.getName());

    List<XmlNamespaces.XmlNamespace> nps = namespaces.consumeNameSpaces();
    if (!nps.isEmpty()) {
      for (XmlNamespaces.XmlNamespace np : nps) {
        sb.append(" xmlns:")
            .append(np.prefix)
            .append("=\"")
            .append(np.uri)
            .append("\"");
      }
    }
    isLastStartTag = true;

    for (Attribute attribute : xmlNodeStartTag.getAttributes().value()) {
      onAttribute(attribute);
    }
  }

  private void onAttribute(Attribute attribute) {
    sb.append(' ');
    String namespace = this.namespaces.getPrefixViaUri(attribute.getNamespace());
    if (namespace == null) {
      namespace = attribute.getNamespace();
    }
    if (namespace != null && !namespace.isEmpty()) {
      sb.append(namespace).append(':');
    }
    String escapedFinalValue = XmlEscaper.escapeXml10(attribute.getValue());
    sb.append(attribute.getName()).append('=').append('"')
        .append(escapedFinalValue).append('"');
  }

  @Override public void onEndTag(XmlNodeEndTag xmlNodeEndTag) {
    --shift;
    if (isLastStartTag) {
      sb.append(" />\n");
    } else {
      appendShift(shift);
      sb.append("</");
      if (xmlNodeEndTag.getNamespace() != null) {
        sb.append(xmlNodeEndTag.getNamespace()).append(':');
      }
      sb.append(xmlNodeEndTag.getName());
      sb.append(">\n");
    }
    isLastStartTag = false;
  }

  @Override public void onCData(XmlCData xmlCData) {
    appendShift(shift);
    sb.append(xmlCData.getValue()).append('\n');
    isLastStartTag = false;
  }

  @Override public void onNamespaceStart(XmlNamespaceStartTag tag) {
    this.namespaces.addNamespace(tag);
  }

  @Override public void onNamespaceEnd(XmlNamespaceEndTag tag) {
    this.namespaces.removeNamespace(tag);
  }

  private void appendShift(int shift) {
    for (int i = 0; i < shift; i++) {
      sb.append('\t');
    }
  }

  public String getXml() {
    return sb.toString();
  }
}
