/*
 * FILE: uaf_demo.c
 * AUTHOR: Rory M [Github username: roddux]
 * UNIT: Cyber Crime and Security Enhanced Programming ISEC3004
 * PURPOSE: To demonstrate use after free vulnerability
 * REFERENCE: Rory. M. (2020). you-me-and-uaf [Repository name]. Github. https://github.com/roddux/you-me-and-uaf
 * COMMENTS: This programs solely belong to @roddux GitHub user.
 * 			 Used for demonstartion purposely only. 
 * 			 Modified print statements, commented and patched by Vansitha Ratnayake.
 * REQUIRES: None
 * LAST MOD: 11/10/2022
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The ultimate goal is to run this exploit function using the dangling pointer */
void exploit() 
{ 
	puts("UAF Exploit Success: Running exploit function"); 
}

/* This is the function that will run first */
void goodfun() 
{ 
	puts("This is the good function!"); 
}

/* 
This object contains a function pointer which will point to one of the above functions
and also a buffer of 20 to store the name of the function so that we can print it on to 
the terminal once it executes. 
*/
typedef struct {
	uint8_t methodName[20];
	uintptr_t (*func)();
} Object;

int main(int argc, char **argv) {
	// unsigned interger pointer to store both addresses of the struct objects
	uintptr_t obj1, obj2;  
	printf("[+] Address of 'goodfun' function: %p\n", goodfun);
	printf("[+] Address of 'exploit' function: %p\n\n", exploit);

	puts("[+] Allocating object obj1");
	// intitally dynamically allocates memory on the heap for a struct of type Object 
	Object *oThing = (void *)malloc(sizeof(Object));

	// if for some some reason the object is not created the program will exit.
	if ( oThing == NULL )
	{ 
		puts("[!] Couldn't allocate!"); return 1; 
	}

	// setting the goodfunc function to the newly created "oThing" struct object
	oThing->func = (void *)goodfun;

	// obj1 Holds a reference of the "oThing" object
	obj1 = (uintptr_t)oThing;

	printf("[+] Address of obj1 in memory    : %ld\n", obj1);
	printf("[+] Address of obj1->func pointer: %p\n\n", oThing->func);

	puts("[+] Calling obj1->func()");
	(*oThing->func)();

	puts("\n[+] Freeing object obj1");
	// here "oThing " object is freed from the heap memory once its work is done
	// THIS IS USED FOR THE EXPLOITATION
	free(oThing);

    // clear the values from both variables that hold references to the object and the address
    // ******* PATCH *******
	obj1 = 0; 
	oThing = NULL;
    // ******* PATCH *******

	// A new object is dynamically allocated memory here to overwite the recently freed block
	puts("[+] Allocating new object obj2");
	Object *oNewObject = (void *)malloc(sizeof(Object));
	// Now unsigned integer obj2 is pointing to this new "oNewObject"
	obj2 = (uintptr_t)oNewObject; 

	// As before if statement checks whether the object was created successfully
	if ( oNewObject == NULL ) 
	{
		puts("[!] Couldn't allocate!"); return 1;
	}

	/* 
	The initial struct object pointed by obj1 was freed and now overwritten by 
	the newly allocated object pointed by obj1. In theory obj1 address should be the same as obj2.
	This is what the if check below does.
	*/
	if ( obj1 != obj2 ) 
	{
		puts("[+] obj2 allocated to a new address. Exploit failed");
		return 1;
	} 
	else 
	{
		puts("[+] obj2 allocated to the same address as free'd obj1!");
	}

	// Now the exploit function is set to the new object to be executed
	oNewObject->func = (void *)exploit;
	printf("[+] Address of obj2 in memory    : %p\n\n", oNewObject);
	printf("[+] Address of obj2->func pointer: %p\n\n", oNewObject->func);

	/* THIS IS WHERE THE EXPLOIT OCCURS
	 The object which was initially created was deallocated from memory.
	 But in reality it was still pointing to that memory block (dangling pointer).
	 Therefore since the new object is created at that memory region where the intial object was
	 we technically still have access to it through the initial object and therefore we can execute it. 
	 Hence the name use after free.*/
	puts("[+] Calling obj1->func()");
	(*oThing->func)();
	free(oNewObject);

	return 0;
}