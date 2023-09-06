---
title: "New Tool: CSSHide - Hiding in plain style"
date: 2023-09-05T15:58:43+01:00
draft: false
---

I've recently been working on a small fun obfuscation tool called [CSSHide](https://github.com/inb1ts/CSSHide), which can encode a payload in the colour values of a CSS file. This was inspired by the payload encoding modules featured at [Maldev Academy](https://maldevacademy.com/), that include encoding payloads as IP addresses, UUIDs, and MAC addresses.

## Why CSS files?

The purpose of the tool is to help facilitate blending in with common browser traffic, which will usually include frequent requests for CSS files that the browser will then use to format the layout of a webpage. For example, here are all the CSS files requested when loading a youtube video:

![Browser CSS file requests](/csshide_browser_requests.png#center)


## How it works

For those unfamiliar with CSS, it is a stylesheet language used to style HTML elements. A CSS file will usually contain multiple "rulesets", which consist of a selector that matches a HTML element name, some properties, and values for those properties. The following image taken from [Mozilla docs](https://developer.mozilla.org/en-US/docs/Learn/Getting_started_with_the_web/CSS_basics) shows what a very basic ruleset might look like:

![CSS ruleset anatomy](/csshide_moz_css_ruleset.png#center)

These rulesets are parsed by the browser, after which the styles are applied to DOM nodes (a representation of the document in-memory that the HTML has been converted to).

The example in the image above uses a colour property - there are multiple ways of representing colour property values in CSS, but two formats in particular are useful for us wanting to encode parts of our payload:

- RGB values: `rgb(152 42 87)`
- Hex values: `#ffb71d`

Each value can hold 3 bytes of information that correspond to Red/Green/Blue (`rgb` also can include a fourth byte for an Alpha value, but the tool currently isn't utilising this). CSSHide works by splitting a payload into 3-byte chunks and formatting those bytes into the colour values. 

Once we've translated our payload into a list of these colour values, the tool generates a CSS file that incorporates them. It starts by creating a short block of CSS variables, which is a quick way of legitimately using many colours in quick succession. Then after the variable section, the remaining colour values are placed in CSS blocks that use a selector randomly picked from a list of generic CSS class selectors that are included in the project.

By default the output is then minified, a process used to save space by removing any whitespace from the file that doesn't impact the CSS property values. The minifying can be disabled with a flag if desired. Some examples of the different output styles are included in the github readme.


The tool is best suited to smaller payloads, as typically CSS files aren't too big. Larger payloads still work (as per the demo below), but defeat the purpose of the obfuscation by producing a suspiciously large CSS file.

https://github.com/inb1ts/CSSHide


## Demo
<br/>
NOTE: This demo is using Havoc's Demon agent as a payload which is 95kb in size - this results in a stupidly large CSS file which would never look legitimate, but it shows that the tool still works with larger payloads.
<br/>

{{< youtube 6jQSTp75KjI>}}