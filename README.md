

# **Api_Hashing**

## [![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=2000&pause=1000&width=435&lines=Welcome+to+Custom-ApiHashing+Repo!!!;Explore+Advanced+Windows+API+Techniques;Master+Function+Resolution+via+Hashing)](https://git.io/typing-svg)

## **Overview**  
The **CustomApiHashing** project demonstrates a powerful method for dynamically resolving API functions using custom hashing techniques. By bypassing traditional `GetProcAddress` and `GetModuleHandle` APIs, this approach avoids detection by hooks set by antivirus or EDR tools.  

This implementation leverages Windows internal structures like the **Process Environment Block (PEB)** and **Export Address Table (EAT)** to enumerate and resolve APIs purely via their hash values.

---

## **Table of Contents**  
- [Overview](#overview)  
- [Purpose](#purpose)  
- [How It Works](#how-it-works)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Code Explanation](#code-explanation)  
- [Disclaimer](#disclaimer)  
- [License](#license)  

---

## **Purpose**  
- Dynamically resolve Windows API functions using custom hashing.  
- Evade detection by avoiding standard Windows API resolution mechanisms.  
- Provide a learning resource for reverse engineers and malware analysts.  

---

## **How It Works**  
1. **Hashing Mechanism:** The API and DLL names are hashed using a custom algorithm.  
2. **Custom Module Retrieval:** Modules are located manually via the **PEB (Process Environment Block)**.  
3. **Function Resolution:** The **Export Address Table (EAT)** is traversed to locate functions using their hash values.  
4. **Dynamic Invocation:** The resolved function is called dynamically.  

### **Key Techniques:**  
- **CustomGetModuleHandle:** Retrieves module handles using their hash values.  
- **CustomGetProcProcess:** Resolves API addresses using hashed names from the EAT.  

---

## **Requirements**  
- Windows Operating System  
- Visual Studio (or compatible IDE)  
- Basic knowledge of Windows Internals  
- Familiarity with the **PEB** and **EAT** structures  

---

## **Installation**  
1. Clone the repository:  
   ```bash
   git clone https://github.com/YourUsername/CustomApiHashing.git
   ```
2. Open the project in **Visual Studio**.  
3. Build the project in **Debug** or **Release** mode.  

---

## **Usage**  
Run the compiled executable to demonstrate API hashing:  
```plaintext
[+] Function found: MessageBoxA
[+] Displaying MessageBox via Hashed API...
```

You should see a **MessageBox** appear on your screen.

---

## **Code Explanation**  

### **Hashing Algorithm:**  
The hashing algorithm converts API and DLL names into unique 32-bit hashes:  
```c
UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String);
```

### **Custom Module and API Resolution:**  
- **GetModuleHandleH:** Finds module handles via hash values using the PEB.  
- **CustomGetProcProcess:** Traverses the Export Address Table to resolve functions.  

### **Example Call:**  
```c
fnMessageBoxA MsgBox = (fnMessageBoxA)CustomGetProcProcess(hUser32, MessageBoxA_HASH);
MsgBox(NULL, "Hello ELB1g", "Hello", MB_OK);
```

---

## **Disclaimer**  
This project is intended for **educational and research purposes only**. Any misuse of this code for malicious purposes is strictly prohibited.  

---

## **License**  
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.  

---

**Happy Hashing! 🚀🔑**

