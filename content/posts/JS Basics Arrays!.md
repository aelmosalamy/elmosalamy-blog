---
title: "Javascript Basics: Arrays!"
date: 2020-07-13
tags: ["javascript"]
---

Hey:wave: there, in this mini-tutorial we are going to go through what is an array, how to create one, learn how to grab items from it, learn how to add items to it and much more! Stay tuned!

I highly advise you to follow along, Javascript is a browser language, and you can follow along right here! In your browser! To do that: Right click anywhere on this page, then click "Inspect", on the side panel that appears, find the ">>" arrow icon, then click "Console", this is where you can type Javascript code!

For starters, let's see what is an array.

In Javascript an array is a collection of many things, Arrays allow you to group elements together and provide you with some cool features such as iteration and mapping!

Right in your console, *see the note above if you haven't seen it already*, copy and paste the following code snippet then press *Enter*:

```javascript
let basket = [":apple:", ":pear:", ":banana:", ":cherries:", ":watermelon:", ":grapes:"];
```

Whoa! we just created our first array; Opss! It's a fruit basket!

We used the keyword `let` to make a variable with the name `basket`, a variable is simply a name we give to something, in this case we gave the name `basket` to the value after the `=` sign, that value is, you guessed it right, our array!

If you take a closer look you will see that our array is enclosed by two square `[` brackets `]` and that, no... not the fruits, the elements inside the array are separated by commas ","

Now it's your turn, from the box below, copy paste your favorite fruits, assemble them in your own array and name the array `myFruits`, we will need your fruits for the next exercise!

```
 :apple: :cherries: :peach: :pineapple: :lemon: :strawberry: :pear: :tangerine: :watermelon: :banana: :green_apple: :grapes: :melon:
```

Remember to place two quotes around each fruit, apparently these are not real fruits, they are emoji fruits, emojis are text and text in Javascript must be enclosed in quotes like this ":apple:" or ':watermelon:'.

You probably made your fruit list by now, here is mine:

```javascript
let myFruits = [":pineapple:", ":strawberry:", ":grapes:"]
```

If everything goes right I should be able to type in `console.log(myFruits)` and see my fruits array in the console! `console.log` is the way to ask Javascript: "What's in there?".

Now let's see how can we get the number of elements inside, type in:

```javascript
console.log(myFruits.length)
```

Voila! You are getting the number of fruits in your array printed out in the console!

Now let's see how can we grab a fruit from our array, to grab the first fruit, pineapple in my case, I will do:

```javascript
let pineapple = myFruits[0];
console.log(pineapple);
// Expected output: :pineapple:
```

In Javascript, you can access elements inside an array using square brackets and a number inside, that number is called the **index**, an index refers to the position of an element. The max index can never be bigger than the `.length` of the array, because Javascript, like most programming languages, feature a zero-based index, that simply means arrays start from 0; accordingly, the first element is referred to as `coolArray[0]`, up in our example, we made a variable, we called it `pineapple` for convenience and we gave it the value of whatever lies in `myFruits[0]`, which happens to be a sweet pineapple when we console.log it!

Now I want you to combine this knowledge with your knowledge of `.length` from the previous exercise and print the last element in `myFruits` to the console, **Hint:** An array with 3 items will have a `.length` of 3; additionally, the last element will have an index of 2 due to the zero-based indexing of JS; I want you to find a solution that no matter what is the length of the array, it will always give the last element. Go ahead and try it yourself!

Congrats to those who solved it! In case you didn't, I am sure that you would've written something along these lines:

```javascript
let lastElement = myFruits[myFruits.length - 1];
console.log(lastElement);
// Expected output: :grapes:
```

The trick here, is that you can feed in the value of `myFruits.length - 1` into the square brackets of `myFruits`, JS automatically evaluated the expression `myFruits.length - 1` to `3 - 1` then to `2`, so the expression really evaluates to `let lastElement = myFruits[2];`; however, what is unique here is the versatility of the solutioon, regardless of the size of our array, whether we decide to add or remove elements, this solution is *always* going to givee the last element, this is a bit of an advanced concept, but whenever you write code you want it to be versatile; ideally, you never want to carve a solution exactly around a specific problem, why so? because you won't always know what you dealing with, so you should anticipate every single possibility and write a general solution that works with them all, anyone can find a solution, but not everyone can come up with **the solution**, I know... it sounds lame; however, most of your time coding will be spent on trying to come up with the **optimal** solution, nowadays, I might see a problem overhead, maybe have 2-3 solutions for it at the top of my head, but still, I would be stuck thinking for hours and hours, coding my way very cautiously, stirring the possibilities in my head, until I come with something I am content with.

Now let's add a fruit to our array, we can do this using `push`, you will understand `push` more later on when talk about objects and methods; anyways, to add a new element we type:

```javascript
myFruits.push(":green_apple:")
console.log(myFruits)
// Expected output: [":pineapple:", ":strawberry:", ":grapes:", ":green_apple:"]
```

Whoa! My fruits array got an extra apple added to it at the end. Again, try it yourself, feel free to copy any fruit and push it to your `myFruits` array.

One good place to read about properties of arrays is the MDN Docs, which is a great place to find information about Javascript and the web, the site is maintained by the folks at Mozilla - yup, the ones behind behind Firefox, take a look on their [reference of push](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/push), they provide a demo, syntax, example and more to make sure you can understand how to use each specific feature in the language.

With that being said, I want you to learn how to fish, there is a method called `splice` which you can use to remove elements from an array, I want you to read its MDN Docs, and use it to remove 2 fruits from your `myFruits` array. **Hint:** Try googling `"mdn array splice"`.