# Type Confusion

## number-coercion
JavaScript's `Number()` function converts values to numbers using implicit type coercion.

**Key behaviors:**
| Input | Output |
|---|---|
| `Number('1')` | `1` |
| `Number('')` | `0` |
| `Number([])` | `0` |
| `Number(['1'])` | `1` |
| `Number(['1','0'])` | `NaN` |
| `Number('hello')` | `NaN` |

**Why `Number(array)` returns `NaN`:**
Array is first converted to string via `.toString()`:
- `['1','0'].toString()` → `"1,0"`
- `Number("1,0")` → `NaN` (comma makes it unparseable)

**NaN comparison behavior:**
`NaN` is never equal to any value, including itself:
```js
NaN === NaN  // false
NaN !== 0    // true  ← can bypass strict inequality checks
NaN !== NaN  // true
```

**Mitigation:**
Always validate type before calling `Number()`:
```js
if (typeof value !== 'string') return reject;
const num = Number(value);
```
