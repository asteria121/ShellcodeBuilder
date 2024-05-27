# ShellcodeBuilder
C언어로 쉘코드를 만들기

[aka. frenchy shellcode](https://www.zscaler.com/blogs/security-research/frenchy-shellcode-wild)

Process Hollowing(RunPE)를 수행하는 쉘코드가 예제로 작성되어있음.

## What is shellcode?
기계어의 집합으로 설명할 수 있음. ASLR에 의해 윈도우 API 들은 주소가 부팅할 떄 마다 바뀜. 따라서 이 주소를 동적으로 구해야함.


# How it works
FS 0x30에는 PEB가 위치함. PEB의 Ldr(0xC)에 로드된 모듈 정보가 위치함.

DLL 주소를 구해 함수의 이름으로 API 주소를 구할 수 있음.

컴파일러의 모든 최적화를 비활성화해야 의도한 쉘코드가 생성됨.

필요한 문자열은 .data 섹션이 아닌 .text 섹션에 생성되도록 하기 위해 다음과 같이 선언해야함.
```c
// .text
char buffer[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', '\0' };

// .data
char buffer[] = "CreateProcessW";
```

위 규칙에 따라 쉘코드로 생성하려는 코드를 작성 후 메모리에서 해당 값을 추출해 유니버셜 쉘코드로 사용할 수 있음.

## Ring3 Unhook
* 시스템 콜 쉘코드
```asm
mov eax, syscallId
mov edx, Wow64Transition
call edx
ret
```
모든 윈도우 API는 최종적으로 ntdll의 함수를 호출하고 해당 함수들은 다음과 같이 커널에 시스템콜을 요청해 최종적으로 윈도우 커널에서 함수를 실행함.

### DLL 매핑
Ring3 후킹이 걸려있을 경우 주소 또는 기계어가 변조되어 시스템콜 번호를 정상적으로 확인할 수 없음. 따라서 DLL을 직접 매핑해 시스템콜 번호를 구할 수 있음. 이 방법으로 매핑한 모듈에서 함수를 호출해도 Ring3 후킹을 우회할 수 있음.

### 시스템콜 번호를 동적으로 구하는 이유
시스템콜 번호는 OS 버전마다 달라지기 때문에 하드코딩을 하거나 동적으로 구해야함.

최종적으로 시스템콜 번호를 기입 후 위 기계어를 실행하면 Ring3 후킹의 영향을 받지 않고 함수를 호출할 수 있음. 다만, PsSetCreateProcessNotifyRoutine, ObRegisterCallback등 Ring0 콜백 또는 SSDT 후킹(KPP로 불가능해짐)은 이 방법으로 우회할 수 없음.
