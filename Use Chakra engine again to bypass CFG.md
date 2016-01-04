#Use Chakra engine again to bypass CFG

By:[exp-sky](https://twitter.com/ExpSky) on 4 Jan 2015

This post is initially inspired by a talk with @TK, during which I learned the process and detail on how to successfully bypass CFG (reference: use Chakra JIT to bypass DEP and CFG). Due to my interest in its technology, I spent some time reading related materials and found another position to bypass CFG. I would like to thanks @TK for enlightening me on the ideas and techniques mentioned in this post.

There are plenty of articles that focus on the analysis of CFG, if you are interested, you may refer to my previous speech on HitCon 2015([《spartan 0day & exploit》](https://github.com/exp-sky/HitCon-2015-spartan-0day-exploit/blob/master/Spartan%200day%20%26%20Exploit-m.pdf)). To be clear, this post is the part that is not revealed in my speech. At this point, the method to implement arbitrary code execution on edge through a write to memory is completely revealed.



##0x01 the function calling logic of Chakra
When the chakra engine calls a function, it will conduct different process based on different function status, for example, the function called first time, the function called multi-times, DOM interface function an the function compiled by jit. Different types of functions have different processing flow, but all processing will be achieved by the Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > > function through calling the Js::JavascriptFunction::CallFunction<1> function.



###1.the first call and the multiple calls of a function
When the following script is called, the function Js::JavascriptFunction::CallFunction<1> will be called by Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >.

```
function test(){}

test();
```

If the function is called for the first time, the execution flow will be:

```
chakra!Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >
	|-chakra!Js::JavascriptFunction::CallFunction<1>
		|-chakra!Js::JavascriptFunction::DeferredParsingThunk
			|-chakra!Js::JavascriptFunction::DeferredParse
			|-chakra!NativeCodeGenerator::CheckCodeGenThunk
				|-chakra!Js::InterpreterStackFrame::DelayDynamicInterpreterThunk
					|-jmp_code
						|-chakra!Js::InterpreterStackFrame::InterpreterThunk
```

If the function is called again, the calling process will be:

```
chakra!Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >
	|-chakra!Js::JavascriptFunction::CallFunction<1>
		|-chakra!NativeCodeGenerator::CheckCodeGenThunk
			|-chakra!Js::InterpreterStackFrame::DelayDynamicInterpreterThunk
				|-jmp_code
					|-chakra!Js::InterpreterStackFrame::InterpreterThunk
```

These two calling flows are almost identical. The mainly difference is when the function is called the first time, it has to use the DeferredParsingThunk function to resolve it. This design is for high efficiency. But the subsequent call will directly execute it.

By analysis, the sub function called by Js::JavascriptFunction::CallFunction<1> is obtained through the data in the Js::ScriptFunction object. The functions called subsequently Js::JavascriptFunction::DeferredParsingThunk and NativeCodeGenerator::CheckCodeGenThunk are both included in the Js::ScriptFunction object. Here are the differences of Js::ScriptFunction in two different calls.

The object Js::ScriptFunction called the first time:

```
0:010> u poi(06eaf050 )
chakra!Js::ScriptFunction::`vftable':

0:010> dd 06eaf050 
06eaf050  5f695580 06eaf080 00000000 00000000

0:010> dd poi(06eaf050+4) 
06eaf080  00000012 00000000 06e26c00 06e1fea0
06eaf090  5f8db3f0 00000000 5fb0b454 00000101

0:010> u poi(poi(06eaf050+4)+0x10)
chakra!Js::JavascriptFunction::DeferredParsingThunk:
```

The object Js::ScriptFunction called the second time:

```
0:010> u poi(06eaf050 )
chakra!Js::ScriptFunction::`vftable':

0:010> dd 06eaf050 
06eaf050  5f695580 1ce1a0c0 00000000 00000000

0:010> dd poi(06eaf050+4)
1ce1a0c0  00000012 00000000 06e26c00 06e1fea0
1ce1a0d0  5f8db9e0 00000000 5fb0b454 00000101

0:010> u poi(poi(06eaf050+4)+0x10)
chakra!NativeCodeGenerator::CheckCodeGenThunk:
```

So the differences between the first call and the subsequent calls are achieved by changing the function pointer in the Js::ScriptFunction object.



###2.jit of the function
Next we’ll look at the jit of the function. Here is the script code for test, which triggers its jit through multiple calling the test1 function.

```
function test1(num)
{
	return num + 1 + 2 + 3;
}

//trigger jit

test1(1);
```

The Js::ScriptFunction object that goes through jit.

```
//new debug, the memory address of the object will be different

0:010> u poi(07103050 )
chakra!Js::ScriptFunction::`vftable':

0:010> dd 07103050 
07103050  5f695580 1d7280c0 00000000 00000000

0:010> dd poi(07103050+4)
1d7280c0  00000012 00000000 07076c00 071080a0
1d7280d0  0a510600 00000000 5fb0b454 00000101

0:010> u poi(poi(07103050+4)+0x10)			//jit code
0a510600 55              push    ebp
0a510601 8bec            mov     ebp,esp
0a510603 81fc5cc9d005    cmp     esp,5D0C95Ch
0a510609 7f21            jg      0a51062c
0a51060b 6a00            push    0
0a51060d 6a00            push    0
0a51060f 68d0121b04      push    41B12D0h
0a510614 685c090000      push    95Ch
0a510619 e802955b55      call    chakra!ThreadContext::ProbeCurrentStack2 (5fac9b20)
0a51061e 0f1f4000        nop     dword ptr [eax]
0a510622 0f1f4000        nop     dword ptr [eax]
0a510626 0f1f4000        nop     dword ptr [eax]
0a51062a 6690            xchg    ax,ax
0a51062c 6a00            push    0
0a51062e 8d6424ec        lea     esp,[esp-14h]
0a510632 56              push    esi
0a510633 53              push    ebx
0a510634 b8488e0607      mov     eax,7068E48h
0a510639 8038ff          cmp     byte ptr [eax],0FFh
0a51063c 7402            je      0a510640
0a51063e fe00            inc     byte ptr [eax]
0a510640 8b450c          mov     eax,dword ptr [ebp+0Ch]
0a510643 25ffffff08      and     eax,8FFFFFFh
0a510648 0fbaf01b        btr     eax,1Bh
0a51064c 83d802          sbb     eax,2
0a51064f 7c2f            jl      0a510680
0a510651 8b5d14          mov     ebx,dword ptr [ebp+14h] //ebx = num
0a510654 8bc3            mov     eax,ebx		//eax = num (num << 1 & 1)
0a510656 d1f8            sar     eax,1			//eax = num >> 1
0a510658 732f            jae     0a510689
0a51065a 8bf0            mov     esi,eax
0a51065c 8bc6            mov     eax,esi
0a51065e 40              inc     eax			//num + 1
0a51065f 7040            jo      0a5106a1
0a510661 8bc8            mov     ecx,eax
0a510663 83c102          add     ecx,2			//num + 2
0a510666 7045            jo      0a5106ad
0a510668 8bc1            mov     eax,ecx
0a51066a 83c003          add     eax,3			//num + 3
0a51066d 704a            jo      0a5106b9
0a51066f 8bc8            mov     ecx,eax
0a510671 d1e1            shl     ecx,1			//ecx = num << 1
0a510673 7050            jo      0a5106c5
0a510675 41              inc     ecx			//ecx = num += 1
0a510676 8bd9            mov     ebx,ecx
0a510678 8bc3            mov     eax,ebx
0a51067a 5b              pop     ebx
0a51067b 5e              pop     esi
0a51067c 8be5            mov     esp,ebp
0a51067e 5d              pop     ebp
0a51067f c3              ret
```

The pointer to NativeCodeGenerator::CheckCodeGenThunk in the Js::ScriptFunction object is changed to a pointer to jit code after jit. The implementation directly called the jit code.

Simply speaking, when the called function passes it parameters, it first rotates one bit left, and pass the values after the lowest bit 1（parameter = (num << 1) & 1）. So the first thing to do after getting the parameter is to rotate one bit right to get the original parameter value. As for why, I suppose it’s caused by the garbage collection mechanism of the script engine, which separates object and data by the lowest bit.

```
chakra!Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >
	|-chakra!Js::JavascriptFunction::CallFunction<1>
		|-jit code
```

When calling the jit function, the calling stack is as the above, this is the method that chakra engine uses to call the jit function.



###3.DOM interface function
To cover everything, there is another kind of function to mention, that’s DOM interface function, a function provided by other engines, such as the rendering engine (theoretically it can be other engines as will).

```
document.createElement("button");
```

On execution, the above script will use the following function calling process, until call the engine that provides the interface function.

```
chakra!Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >
	|-chakra!Js::JavascriptFunction::CallFunction<1>
		|-chakra!Js::JavascriptExternalFunction::ExternalFunctionThunk //call dom interface function
			|-dom_interface_function	//EDGEHTML!CFastDOM::CDocument::Trampoline_createElement
```

When calling the interface function, the Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > > function and the function object used in the subsequent process differ from the ones used previously, it is the Js::JavascriptExternalFunction object. Then similar to the previosfunction call, it also resolves the function pointer in their subject and calls it; finally it enters the wanted DOM interface function.

```
0:010> u poi(06f2cea0)
chakra!Js::JavascriptExternalFunction::`vftable':

0:010> dd 06f2cea0 
06f2cea0  5f696c4c 06e6f7a0 00000000 00000000

0:010> dd poi(06f2cea0+4)
06e6f7a0  00000012 00000000 06e76c00 06f040a0
06e6f7b0  5f8c6130 00000000 5fb0b454 00000101

0:010> u poi(poi(06f2cea0+4)+0x10)
chakra!Js::JavascriptExternalFunction::ExternalFunctionThunk:
```

These are the different call methods that chakra engine uses to call different types of functions.



##0x02 Exploit and Exploitation
After describing the call methods for all sorts of chakra engines, now we’ll check out the very important cog vulnerability. As mentioned above, the first calling process differs from the sub sequent ones. Let’s look at the logic here; the following is the call stack:

```
//the first call
chakra!Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > >
	|-chakra!Js::JavascriptFunction::CallFunction<1>
		|-chakra!Js::JavascriptFunction::DeferredParsingThunk
			|-chakra!Js::JavascriptFunction::DeferredParse    //obtain NativeCodeGenerator::CheckCodeGenThunk function
			|-chakra!NativeCodeGenerator::CheckCodeGenThunk
				|-chakra!Js::InterpreterStackFrame::DelayDynamicInterpreterThunk
					|-jmp_code	
						|-chakra!Js::InterpreterStackFrame::InterpreterThunk
```

What is not mentioned above is the Js::JavascriptFunction::DeferredParse function in the above process. Function resolution related work is conducted in this function, and this function returns the pointer value of NativeCodeGenerator::CheckCodeGenThunk, then returns Js::JavascriptFunction::DeferredParsingThunk and calls it. The pointer of NativeCodeGenerator::CheckCodeGenThunk is also obtained through resolving the Js::JavascriptFunction object. Here is the code.

```
int __cdecl Js::JavascriptFunction::DeferredParsingThunk(struct Js::ScriptFunction *p_script_function)
{
  NativeCodeGenerator_CheckCodeGenThunk = Js::JavascriptFunction::DeferredParse(&p_script_function);
  return NativeCodeGenerator_CheckCodeGenThunk();
}
```

```
.text:002AB3F0 push    ebp
.text:002AB3F1 mov     ebp, esp
.text:002AB3F3 lea     eax, [esp+p_script_function]
.text:002AB3F7 push    eax             ; struct Js::ScriptFunction **
.text:002AB3F8 call    Js::JavascriptFunction::DeferredParse
.text:002AB3FD pop     ebp
.text:002AB3FE jmp     eax
```

On this jump position, no CFG check is made on the function pointer in eax. Therefore, this can be used to hijack the eip. But first you need to know how the function pointer NativeCodeGenerator::CheckCodeGenThunk returned by the Js::JavascriptFunction::DeferredParse function is resolved through the Js::ScriptFunction object. Here is the resolution process.


```
0:010> u poi(070af050)
chakra!Js::ScriptFunction::`vftable':

0:010> dd 070af050 + 14
070af064  076690e0 5fb11ef4 00000000 00000000

0:010> dd 076690e0 + 10
076690f0  076690e0 04186628 07065f90 00000000

0:010> dd 076690e0 + 28
07669108  07010dc0 000001a8 00000035 00000000

0:010> dd 07010dc0 
07010dc0  5f696000 05a452b8 00000000 5f8db9e0

0:010> u 5f8db9e0
chakra!NativeCodeGenerator::CheckCodeGenThunk:
```

As shown above, Js::JavascriptFunction::DeferredParse gets the NativeCodeGenerator::CheckCodeGenThunk function pointer by resolving the Js::ScriptFunction object, the resolving method is abbreviated as [[[Js::ScriptFunction+14]+10]+28]+0c. So just by forging the data in this memory, it can trigger the call of Js::JavascriptFunction::DeferredParse by calling the function, further to hijack the eip, as shown below.

```
0:010> g
Breakpoint 0 hit
eax=603ba064 ebx=063fba10 ecx=063fba40 edx=063fba40 esi=00000001 edi=058fc6b0
eip=603ba064 esp=058fc414 ebp=058fc454 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000283
chakra!`dynamic initializer for 'DOMFastPathInfo::getterTable''+0x734:
603ba064 94              xchg    eax,esp
603ba065 c3              ret
```

By this way, cfg is bypassed and eip is hijacked. This method is simple and stable. It’s convenient to use when you get access to read and write the memory. This exploit has been reported to Microsoft on 25th July, 2015.



##0x03 Mitigation
Microsoft has fixed all the exploits in this post. The mitigation plan is relatively easy, which is to add cft check at this jump.

```
.text:002AB460 push    ebp
.text:002AB461 mov     ebp, esp
.text:002AB463 lea     eax, [esp+arg_0]
.text:002AB467 push    eax
.text:002AB468 call    Js::JavascriptFunction::DeferredParse
.text:002AB46D mov     ecx, eax        ; this
.text:002AB46F call    ds:___guard_check_icall_fptr  //add cfg check
.text:002AB475 mov     eax, ecx
.text:002AB477 pop     ebp
.text:002AB478 jmp     eax
```



##Reference
[《Bypass DEP and CFG using JIT compiler in Chakra engine》](http://xlab.tencent.com/en/2015/12/09/bypass-dep-and-cfg-using-jit-compiler-in-charkra-engine/)

[《spartan 0day & exploit》](https://github.com/exp-sky/HitCon-2015-spartan-0day-exploit/blob/master/Spartan%200day%20%26%20Exploit-m.pdf)