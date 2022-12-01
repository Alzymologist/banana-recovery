
# Crate `banana_recovery`

## Overview

This is a lib crate for recovering secrets from a set of shares generated using [banana split protocol](https://github.com/paritytech/banana_split).  

The goal is only to *recover* secrets, there is no secret generation part present here.  

The code is following the published javascript code for banana split recovery from <https://github.com/paritytech/banana_split>. The combining of shares into encrypted secret is re-written in rust and generally follows the published javascript code for Shamir's Secret Sharing from <https://www.npmjs.com/package/secrets.js-grempe>.  

## Comments  

In principle, the Shamir's Secret Sharing from <https://www.npmjs.com/package/secrets.js-grempe> supports `bits` values (i.e. the value n defining the size of Galios field `GF(2^n)` and the possible number of shares) in range `3..20`. The bits are set up during the `init` (here: <https://github.com/grempe/secrets.js/blob/master/secrets.js#L472>), defaulting to `8`. The `V1` in banana split uses the default value. This crate supports range `3..20`, could be useful in case other banana split versions appear.  

When pre-calculating logarithms and exponents values within `GF(2^n)`, all exponents are generated in same order as they are written in the collecting vector, so naturally all of them are existing. Due to the properties of GF, all logarithms are also get filled in eventually, except `log[0]` that remains undetermined.  
During Lagrange polynomial calculation, certain `log[i]` values are summed up, and the resulting `product` is used to calculate the exponent `exp[product]` to be xored with final collected value. Summing logs and calculating exponent from sum is a common convenient way of multiplying values.  
When `log[0]` get addressed, it means that 0 participates in multiplication, the total multiplication result is 0, xoring will not change anything. So the whole cycle element gets skipped in this case.  

This is a continuation of development of <https://github.com/paritytech/banana-recovery-rust>, at commit `fa8513f6a734c6321c91dcb7fd898ab353ce009a`.  

