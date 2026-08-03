# XSS Attack Testing Guide

## Quick Start

1. **Start the server:**
   ```bash
   npm start
   ```

2. **Open your browser** and navigate to `http://localhost:3000`

## Testing Methods

### Method 1: Using URL Parameters (Recommended)

#### Test Vulnerable Mode (Detection):
```
http://localhost:3000/search?mode=vulnerable&q=<script>alert('XSS_ATTACK')</script>
```

#### Test Secure Mode (Prevention):
```
http://localhost:3000/search?mode=secure&q=<script>alert('XSS_ATTACK')</script>
```

### Method 2: Using the UI Mode Buttons

1. Visit `http://localhost:3000/search?q=<script>alert('XSS')</script>`
2. Click the **🔴 Vulnerable Mode** button to see detection
3. Click the **🟢 Secure Mode** button to see prevention

## Example Attack Payloads to Test

### Basic Script Tag Attack:
```
http://localhost:3000/search?mode=vulnerable&q=<script>alert('XSS')</script>
```

### Image Tag with onerror:
```
http://localhost:3000/search?mode=vulnerable&q=<img src=x onerror=alert('XSS')>
```

### Iframe Attack:
```
http://localhost:3000/search?mode=vulnerable&q=<iframe src=javascript:alert('XSS')></iframe>
```

### Event Handler Attack:
```
http://localhost:3000/search?mode=vulnerable&q=<div onclick=alert('XSS')>Click me</div>
```

### JavaScript Protocol:
```
http://localhost:3000/search?mode=vulnerable&q=<a href=javascript:alert('XSS')>Link</a>
```

## What to Look For

### In Vulnerable Mode (Detection):
- ✅ **Status Card**: Shows red "🚨 DETECTION" message
- ✅ **Attack Patterns**: Red indicators for detected patterns
- ✅ **Attack Score**: Higher numbers (1-9)
- ✅ **Flow Diagram**: Shows "⚠️ Attack" in step 5
- ✅ **Charts**: Shows detected patterns in red
- ✅ **Output**: Raw script tags visible in innerHTML

### In Secure Mode (Prevention):
- ✅ **Status Card**: Shows green "✅ PREVENTION SUCCESSFUL" message
- ✅ **Attack Patterns**: Still shows detected patterns (for analysis)
- ✅ **Flow Diagram**: Shows "✓ Safe" in step 5
- ✅ **Charts**: Shows high security effectiveness (green)
- ✅ **Output**: Script tags encoded as `&lt;script&gt;` (visible as text)
- ✅ **Encoding Comparison**: Shows before/after encoding

## Understanding the Results

### Attack Score:
- **0**: No malicious patterns detected
- **1-3**: Low risk
- **4-6**: Medium risk
- **7-9**: High risk (multiple attack vectors)

### Security Effectiveness:
- **0%**: Vulnerable mode (no protection)
- **100%**: Secure mode (full encoding applied)

### Pattern Detection:
The system checks for:
1. `<script>` tags
2. `</script>` closing tags
3. `onerror` event handlers
4. `onclick` event handlers
5. `javascript:` protocol
6. `<img>` tags
7. `<iframe>` tags
8. `eval()` function calls
9. `alert()` function calls

## Testing Checklist

- [ ] Test basic script tag in vulnerable mode
- [ ] Test basic script tag in secure mode
- [ ] Test image tag with onerror
- [ ] Test iframe attack
- [ ] Test event handler attacks
- [ ] Verify charts update correctly
- [ ] Verify flow diagram shows correct path
- [ ] Check encoding comparison shows difference
- [ ] Verify status messages are accurate

## Browser Console

Open browser DevTools (F12) to see:
- Any CSP violations (should appear in secure mode)
- Network requests
- Console errors (if any)

## Tips

1. **URL Encoding**: If copying URLs, make sure special characters are properly encoded
2. **Compare Modes**: Test the same payload in both modes to see the difference
3. **Check innerText vs innerHTML**: The system uses innerText to detect successful encoding
4. **Multiple Patterns**: Try payloads with multiple attack patterns to see higher attack scores


