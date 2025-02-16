
# Create a cryptographic algorithm using C 

This is where I built a simple math based algorithm where you can encrypt your string message into a hashing values something like SHA256, djb2 hash and md5 hash 


## SetUp - for Contribution

I am using bashbs [build system created by dr jonas birch] try that out over
https://repo.doctorbirch.com

if you are not using that just create a Makefile conf and there you go!



### Some Talk

I have a npm package called "felixhash" over there I have tried to do the same (~) in typescript you can check that out obviously.
https://github.com/felixoder/cryptohash [give me a star]

and one thing creating something exactly like SHA256, Keccak256 is a huge job anit will be hard to do. the algorithm I have tried to create is not 100% of SHA algo but I have tried to create something like that.

## Resource 

For Djb2 hash refer to this -  
https://theartincode.stanis.me/008-djb2/

For MD5 hash refer to this - 
https://en.wikipedia.org/wiki/MD5

For my own hash fucntion I have created a notion doc where I have created a mindmap of how to create something like this 
check this plz

https://cedar-puppet-c60.notion.site/Create-a-Cryptographic-algorithm-using-C-14069222faa880ff8204ce76edaed56f

## Testing

```bash

./SHA
Enter the value: Hey debayan here, star this repo for sure
felix Hash: bade8d80d98d9c6032f1c4991003aad679e393ddc660d17e590797e0fc1532ac
Djb2 Hash: 193458859
MD5 Hash: d0eedb799584d850fdd802fd3c27ae34

```

## Contributing


Contributions are always welcome!

1. Fork the repository
2. Append the changes

## Authors

- [@debayan](https://www.github.com/felixoder)


