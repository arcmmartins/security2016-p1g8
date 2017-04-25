from Crypto.Random import random

class DHUtils:
    # sv diffie hellman
    private = random.getrandbits(1024)
    prime = 0xeb8d2e0bfda29137c04f5a748e88681e87038d2438f1ae9a593f620381e58b47656bf5386f7880da383788a35d3b4a6991d3634b149b3875e0dccff21250dccc0bf865a5b262f204b04e38b2385c7f4fb4e2058f73a8f65252e556b667b1570465b2f6d1beeab215b05cd0e28b9277f3f48c01b1619b30147fcfc87b5b6903e70078babb45c2ee6a6bd4099ab87b01ba09a38c36279b46309ef0df5e45e15df9ba5cb296baa535c60bb0065669fd8078269eb759416d9b27229f9cb6e5f60f7d8756f6f621ad519745f914e81a7c8d09b3c7a764863dd5d5f2bcab5ef283aa3781c985d07f2b1aafb2e7747b3217dbbfea2e91484c31a00e22467c0c7f9d40f73d392594c516b302aa7c1aa6ca5a0b346cc6bfc1cd201dfe78aabf717f6c69f30a896567b07090e352e87fd698128da0594916d27203e22b7bb1f7f860842fd0aee2e532a077629451ef86163fdf567048266050a473d4db27e85a33bc985b16569afddaa9a94a5b9155b32b78c84b261ce7acf7d8d0ef23d4e1d028104aff6a77cab79ecdf7dd19468f67d3cb9b86835cce1a87dbf4b2d3100a9bd7a9e251272bf4e2fed2c2f7535e556b8cc1fc6fcfc1a2ca188c02ea9298bb4a7f12afd4164ad9211f7935f51be3d9d932e835a1fd322e7db75ba587021f8c730d7f021905e89a0ddb80bf8ea53b8f1603cf08c734aadfe7f9184e0de9e91651c3d88deb68fd1bc0188e479747caab9a157ef6ec68295a1bfb6391973364987cda6c7817dfee2ab9d4e0eaefb29154f23eafedcab06d67fbcc5d1788a20315c50f9c6471dbb45419b07ddec0d507c16a0b7e2d79290d3115edcdc2996897015dfa430389a1d63533e52aa6309c76e7069e0a99af65702036e7829bc8e86ad3e23983debf72c82d8e3a2e9d767cccfb2abed6b0b0c9f217bb496ea816ea3c32111f60916d91f8a97cfa38b163ca1261733cd98cb2ff77a7ee9290bda74be8dc206489d06abca4e5ae82ae4923fa43b451fa419da06d74f15e4efc4852bf5edf37e581edeaaefd28a8b3c672bb76068439635adecebaf8311d4018fe8e62892f784d7a44747178c4cb540c58e5e2a660a3f02c873d12b43f0643d3794d8b310fe9fa6d798e0724d38c85c9e4d5c8c9ba645f3411dd4645ef1ef1dad9ba60325b12def1bd706d11386045e450fee2a60c88cf6387dea0521acc4d869fb146a47ef4e34480d30f84ffa0e0e0a4a4c7f1b0a8e642223e8bec4d1c8effd98ba235dc5c5f7e296ecd7476595ef17371a1aec3a38c3e7f7e08e7b5e7c927f5843062f753e5ee85f7e64164dd0ccb7261d4ca3a35058ca88f87275a292e96100005c025742f85be7a2598406b9c792f2ba2a496f8074d899821110effb184e3c679330b182a8c14ba1699f3761168d64e838829c0250c6be87bc8dc2b29954bf6cb450ba7bed793cf97
    pr_root = 5
    my_pub = pow(pr_root, private, prime)
    other_pub = -1
    shared_key = -1