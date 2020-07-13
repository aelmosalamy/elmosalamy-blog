---
title: "Javascript Basics: Arrays!"
date: 2020-07-13
tags: ["javascript"]
---

Hey:wave: there, in this mini-tutorial we are going to go through what is an array, how to create one, learn how to grab items from it, learn how to add items to it and much more! Stay tuned!

{{<note>}}
I highly advise you to follow along, Javascript is a browser language, and you can follow along right here! In your browser! To do that: Right click anywhere on this page, then click "Inspect", on the side panel that appears, find the ">>" arrow icon, then click "Console", this is where you can type Javascript code!
{{</note>}}

For starters, let's see what is an array.

In Javascript an array is a collection of many things, Arrays allow you to group elements together and provide you with some cool features such as iteration and mapping!

Right in your console, *see the note above if you haven't seen it already*, copy and paste the following code snippet then press *Enter*:

```javascript
var basket = [":apple:", ":pear:", ":banana:", ":cherries:", ":watermelon:", ":grapes:"];
```

Whoa! we just created our first array; Opss! It's a fruit basket!

We used the keyword `var` to make a variable with the name `basket`, a variable is simply a name we give to something, in this case we gave the name `basket` to the value after the `=` sign, that value is, you guessed it right, our array!

If you take a closer look you will see that our array is enclosed by two square `[` brackets `]` and that, no... not the fruits, the elements inside the array are separated by commas ","

Now it's your turn, from the box below, copy paste your favorite fruits, assemble them in your own array and name the array `myFruits`, we will need your fruits for the next exercise!

```
 :apple: :cherries: :peach: :pineapple: :lemon: :strawberry: :pear: :tangerine: :watermelon: :banana: :green_apple: :grapes: :melon:
```

{{<warning>}}
Remember to place two quotes around each fruit, apparently these are not real fruits, they are emoji fruits, emojis are text and text in Javascript must be enclosed in quotes like this ":apple:" or ':watermelon:'.
{{</warning>}}

You probably made your fruit list by now, here is mine:

```javascript
var myFruits = [":pineapple:", ":strawberry:", ":grapes:"]
```

If everything goes right I should be able to type in `console.log(myFruits)` and see my fruits array in the console! `console.log` is the way to ask Javascript: "What's in there?".

Now let's see how can we get the number of elements inside, type in:

```javascript
console.log(myFruits.length)
```

Voila! You are getting the number of fruits in your array printed out in the console!

Now let's add a fruit to our array, we can do this using `push`, you will understand `push` more later on when talk about objects and methods; anyways, to add a new element we type:

```javascript
myFruits.push(":green_apple:")
console.log(myFruits)
// Expected output: [":pineapple:", ":strawberry:", ":grapes:", ":green_apple:"]
```

Whoa! My fruits array got an extra apple added to it at the end. Again, try it yourself, feel free to copy any fruit and push it to your `myFruits` array.

One good place to read about properties of arrays is the MDN Docs, which is a great place to find information about Javascript and the web, the site is maintained by the folks at Mozilla - yup, the ones behind behind Firefox, take a look on their [reference of push](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push), they provide a demo, syntax, example and more to make sure you can understand how to use each specific feature in the language.

With that being said, I want you to learn how to fish, there is a method called `splice` which you can use to remove elements from an array, I want you to read its MDN Docs, and use it to remove 2 fruits from your `myFruits` array. **Hint:** Try googling `"mdn array splice"`.