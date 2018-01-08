Jazmine Blockchain

See https://jazmine.io/ for info.

This is Jazmined, The blockchain daemon, configured to build using Visual Studio C++

NOTE: mining is temporarily disabled in this version, until some code issues are resolved. If you 
want to mine jazmine, please use the Linux version.

```
NOTE: This software will start an RPC/HTTP server listening on your computer on localhost (127.0.0.1). 
It is not accessible to the outside, HOWEVER please note that a specially scripted javascript code 
on a remote web site could possibly manipulate the rpc/http server running on your machine. 
```

At the moment do not "surf the web" while running this software, it's potentially an issue. 

Will have authorization added to future release.

(The wallet does not listen for RPC commands on Windows)



This software is based on code from CryptoNote, Bytecoin and Monero, with some modifications and updates.

To BUILD:

Open the solution file in Visual Studio.
Note: You will need to install the boost headers *and* the boost libs using Nuget.

Example: 

```
PM> Install-Package boost -Version 1.66.0
PM>  Install-Package boost-vc141 -Version 1.66.0 
```

