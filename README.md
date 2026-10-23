# win-def-clickfix
**win-def-clickfix** is a run-1 detection replica for **ClickFix / Win+R** command lines, rebuilt by reverse-engineering **Microsoft Defender**'s `mpengine.dll`.<br>
It runs a command line through the recovered normalizer/deobfuscator (`FUN_1800a2500`) and matches it against the **807 VDM-extracted `CMDHSTR_EXT` signatures**, evaluated with their real `condition:` logic.<br>
It also ships the extracted **`BMClientV1`** neural network — a stateful GRU — executed in **pure numpy**, alongside scanners for the engine's other recovered paths (AMSI, AMSI-UAC, RPF/JIT, WMI, script hosts, paste obfuscation).<br>

### Please leave a star if this project helps you
