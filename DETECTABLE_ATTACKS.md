# XSS Attack Detection Capabilities

This XSS detection system can identify the following types of Cross-Site Scripting attacks:

## 1. Script Tag Attacks
- **Basic Script Injection**: `<script>alert('XSS')</script>`
- **Script with Attributes**: `<script type="text/javascript">malicious_code</script>`
- **Closing Script Tags**: `</script>` patterns

## 2. Event Handler Attacks
- **onerror Events**: `<img src=x onerror=alert('XSS')>`
- **onclick Events**: `<div onclick=alert('XSS')>Click me</div>`
- **onmouseover Events**: `<div onmouseover="alert('XSS')">Hover</div>`
- **onload Events**: `<body onload=alert('XSS')>`
- **Other Event Handlers**: onfocus, onblur, onchange, etc.

## 3. JavaScript Protocol Attacks
- **JavaScript URLs**: `<a href=javascript:alert('XSS')>Link</a>`
- **Iframe with JavaScript**: `<iframe src=javascript:alert('XSS')></iframe>`
- **Embed with JavaScript**: `<embed src=javascript:alert('XSS')>`

## 4. Image Tag Attacks
- **Broken Image with onerror**: `<img src=x onerror=alert('XSS')>`
- **Image with Malicious Source**: `<img src="javascript:alert('XSS')">`
- **Image with Event Handlers**: `<img onload=alert('XSS') src=valid.jpg>`

## 5. Iframe Attacks
- **Iframe with JavaScript**: `<iframe src=javascript:alert('XSS')></iframe>`
- **Iframe with Data URI**: `<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>`

## 6. Eval Function Attacks
- **Direct eval()**: `eval('alert("XSS")')`
- **Eval in Strings**: `eval(String.fromCharCode(...))`
- **Function Constructor**: `new Function('alert("XSS")')()`

## 7. Alert Function Attacks
- **Direct alert()**: `alert('XSS')`
- **Window.alert()**: `window.alert('XSS')`
- **Nested alerts**: `alert(alert('XSS'))`

## 8. SVG-based Attacks
- **SVG with Script**: `<svg><script>alert('XSS')</script></svg>`
- **SVG with onload**: `<svg/onload=alert('XSS')>`
- **SVG with Event Handlers**: `<svg onmouseover="alert('XSS')">`

## 9. Form-based Attacks
- **Form with Script**: `<form><button formaction="javascript:alert('XSS')">Submit</button></form>`
- **Input with Event Handlers**: `<input onfocus=alert('XSS') autofocus>`

## 10. Link-based Attacks
- **JavaScript Protocol Links**: `<a href="javascript:alert('XSS')">Click</a>`
- **Data URI Links**: `<a href="data:text/html,<script>alert('XSS')</script>">Link</a>`

## Detection Patterns

The system detects attacks by checking for:

1. **Script Tags**: `<script` patterns (opening and closing)
2. **Event Handlers**: `onerror`, `onclick`, `onload`, etc.
3. **JavaScript Protocol**: `javascript:` in URLs
4. **Image Tags**: `<img` with suspicious attributes
5. **Iframe Tags**: `<iframe` with malicious sources
6. **Eval Functions**: `eval(` patterns
7. **Alert Functions**: `alert(` patterns

## Attack Score Calculation

Each detected pattern contributes to an **Attack Score**:
- Higher scores indicate more attack patterns detected
- Score = Number of different attack patterns found
- Maximum score: 9 (all patterns detected)

## Examples of Detectable Payloads

### Basic Attacks:
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<iframe src=javascript:alert('XSS')></iframe>
<div onclick=alert('XSS')>Click me</div>
<a href=javascript:alert('XSS')>Link</a>
```

### Advanced Attacks:
```
<svg/onload=alert('XSS')>
<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>
<input onfocus=alert('XSS') autofocus>
<embed src=javascript:alert('XSS')>
```

### Encoded Attacks (may be detected depending on encoding):
```
&lt;script&gt;alert('XSS')&lt;/script&gt;
%3Cscript%3Ealert('XSS')%3C/script%3E
```

## Limitations

The system uses **pattern-based detection**, which means:

1. **May produce False Positives**: Legitimate code containing these patterns might be flagged
2. **May miss Advanced Obfuscation**: Heavily obfuscated attacks might not be detected
3. **Encoding-dependent**: Some encoded attacks may bypass detection
4. **Context-aware**: The system doesn't understand HTML context, only patterns

## Best Practices

For accurate detection:
1. Always provide **Ground Truth** labels when scanning
2. Use the **K-Fold Cross-Validation** to assess model performance
3. Review **False Positives** and **False Negatives** in the metrics
4. Combine with other security measures (CSP, input validation, output encoding)

