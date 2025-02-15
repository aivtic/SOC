
## **Introduction to YARA 101 Lab**

### **Lab Objective**:
The goal of this lab is to introduce students to **YARA** a powerful tool used for malware detection based on file patterns. Students will learn how to write, optimize, and test YARA rules using practical scenarios and sample files. By the end of the lab, students will have a good understanding of YARA rule creation, file analysis, and how to use YARA for malware detection.

At the end of the lab, students will submit a **report in PDF format** documenting the following:
- YARA rules created.
- Files analyzed (benign and malicious).
- Test results and explanations.
- Challenges encountered during the lab.

---

### **Required Tools**:
1. **YARA**: Download and install YARA from [VirusTotal GitHub](https://github.com/VirusTotal/yara).
2. **Sample Files**: Download the sample files for analysis (described below).
3. **Text Editor**: Use a text editor (Visual Studio Code, Sublime Text, or Notepad++) to write YARA rules.
4. **Terminal**: You will need to use a terminal or command-line interface to execute YARA commands.

---

### **Lab Steps and Instructions**:

---

### **Part 1: Introduction to YARA**

#### **Objective**:
Introduce students to the basic syntax and structure of YARA rules, and give them their first task to create simple YARA rules.

---

#### **Step 1.1: Writing a Basic YARA Rule**

**YARA Rule Structure**:
- **Meta**: Contains metadata about the rule.
- **Strings**: Lists strings or byte patterns the rule will search for.
- **Condition**: Defines the logical conditions under which the rule will match files.

**Example of a simple YARA rule**:
```yara
rule SampleRule
{
    meta:
        description = "Detects 'malicious_string' or a byte pattern"
        author = "Instructor"
        date = "2025-01-23"

    strings:
        $text_string = "malicious_string"
        $byte_pattern = { E8 34 12 56 }

    condition:
        $text_string or $byte_pattern
}
```

#### **Task 1**: Create a YARA rule to detect the string `"malicious_string"` in any file.

---

#### **Step 1.2: Testing Your Rule**

**Sample Files for Testing**:
- **benign_file.txt**:
  - Content: `"This is a safe document."`
  
- **malware_file.exe**:
  - Content: `"This file contains malicious_string."`

**Test Command**:
```bash
yara -r detect_string_rule.yara /path/to/test_directory/
```

#### **Expected Outcome**:  
- The rule should **not** match **benign_file.txt**.
- The rule should match **malware_file.exe**.

---

### **Part 2: Writing Basic YARA Rules**

#### **Objective**:
Students will combine string matching with byte pattern matching to write more comprehensive rules for malware detection.

---

#### **Step 2.1: Detecting Malware via Strings and Byte Patterns**

**Scenario**:  
You are tasked with detecting a piece of malware called **EvilSoftware**. The malware contains the string `"EvilSoftware"`, and its byte signature is `{ E8 34 12 56 }`.

#### **Task 2**:
1. Write a YARA rule to detect the malware based on the string `"EvilSoftware"` and the byte pattern `{ E8 34 12 56 }`.

**Example Rule**:
```yara
rule EvilSoftwareDetection
{
    meta:
        description = "Detects EvilSoftware string and byte pattern"
        author = "Student"
        date = "2025-01-23"

    strings:
        $evil_string = "EvilSoftware"
        $evil_bytes = { E8 34 12 56 }

    condition:
        $evil_string or $evil_bytes
}
```

#### **Sample Files for Testing**:
- **benign_file.txt**:
  - Content: `"This is a safe document."`
  
- **evil_sample.exe** (malicious):
  - Content: `"This file contains EvilSoftware code."`
  
**Test Command**:
```bash
yara -r evil_software_rule.yara /path/to/test_files/
```

#### **Expected Outcome**:
- The rule should match **evil_sample.exe**.
- The rule should **not** match **benign_file.txt**.

---

### **Part 3: Advanced Rule Writing**

#### **Objective**:
Students will explore advanced YARA rule techniques, such as using regular expressions and combining multiple detection methods.

---

#### **Step 3.1: Detecting Malware with Regular Expressions**

**Scenario**:  
You are tasked with detecting various versions of a malware family. The filenames follow the pattern `"malware_v1"`, `"malware_v2"`, and so on.

#### **Task 3**:
1. Write a YARA rule to detect files whose names match the pattern `"malware_vX"`, where `X` is any number.

**Example Rule**:
```yara
rule DetectMalwareByRegex
{
    meta:
        description = "Detects malware versions by regex pattern"
        author = "Student"
        date = "2025-01-23"

    strings:
        $filename_pattern = /malware_v\d+/

    condition:
        $filename_pattern
}
```

#### **Sample Files for Testing**:
- **malware_v1.exe**:
  - Content: `"Malicious content"`
  
- **malware_v2.exe**:
  - Content: `"Malicious content"`
  
- **random_file.txt**:
  - Content: `"Safe text"`

**Test Command**:
```bash
yara -r regex_rule.yara /path/to/test_files/
```

#### **Expected Outcome**:
- The rule should match **malware_v1.exe** and **malware_v2.exe**.
- The rule should **not** match **random_file.txt**.

---

### **Part 4: Performance Optimization and Advanced Testing**

#### **Objective**:
Students will learn to optimize their YARA rules to minimize false positives and improve performance.

---

#### **Step 4.1: Avoiding False Positives**

**Scenario**:  
You need to detect files with the string `"malicious_behavior"` but **exclude** any files that contain the string `"success"`, which is often found in benign files.

#### **Task 4**:
1. Write a YARA rule to detect **malicious_behavior** but exclude files containing `"success"`.

**Example Rule**:
```yara
rule DetectMaliciousBehavior
{
    meta:
        description = "Detects malicious behavior, excluding 'success'"
        author = "Student"
        date = "2025-01-23"

    strings:
        $malicious_behavior = "malicious_behavior"
        $success = "success"

    condition:
        $malicious_behavior and not $success
}
```

#### **Sample Files for Testing**:
- **benign_file_1.txt**:
  - Content: `"This file is safe. success"`
  
- **malware_1.exe**:
  - Content: `"This is a malicious file with malicious_behavior."`
  
- **malware_2.exe**:
  - Content: `"This file contains both malicious_behavior and success."`

**Test Command**:
```bash
yara -r optimized_rule.yara /path/to/test_files/
```

#### **Expected Outcome**:
- The rule should match **malware_1.exe**.
- The rule should **not** match **benign_file_1.txt** or **malware_2.exe** (due to the exclusion of `"success"`).

---

#### **Step 4.2: Hash-based Detection**

**Scenario**:  
You know the hash of a known malware file is `b6d81c095490d1e9295c7cfcf9249f13`.

#### **Task 5**:
1. Write a YARA rule to detect the malware file based on its hash.

**Example Rule**:
```yara
rule DetectByHash
{
    meta:
        description = "Detects malware by hash"
        author = "Student"
        date = "2025-01-23"

    hash:
        $hash = "b6d81c095490d1e9295c7cfcf9249f13"

    condition:
        $hash
}
```

#### **Sample Files for Testing**:
- **known_malware.exe** (with the hash `b6d81c095490d1e9295c7cfcf9249f13`):
  - Content: `"Malware with known hash"`

- **benign_file.txt**:
  - Content: `"This file is safe."`

**Test Command**:
```bash
yara -r hash_rule.yara /path/to/test_files/
```

#### **Expected Outcome**:
- The rule should match **known_malware.exe**.
- The rule should **not** match **benign_file.txt**.

---

### **Part 5: Final Task and Real-World Scenario (1 Hour)**

#### **Objective**:
Students will combine all the techniques they’ve learned to create a comprehensive YARA rule.

---

#### **Step 5.1: Comprehensive Malware Detection Rule**

**Scenario**:  
You need to detect a piece of malware based on:
- The string `"infected_file"`.
- The byte sequence `{ 12 AB 34 CD }`.
- The file was modified in the last 30 days.
- Exclude files from trusted sources based on hash.

#### **Task**:
1. Write a comprehensive YARA rule to detect this malware.

**Test Files**:
- **malware_1.exe** (should match)
- **trusted_file.exe** (should not match)
- **benign_file.txt** (should not match)

---

### **Conclusion and Report Submission**

At the end of the lab, students will prepare a **PDF report** containing:

1. **A summary of YARA rules** they created.
2. **Screenshots and output** from YARA commands used to test the rules.
3. **Explanation** of what each rule detects and how it works.
4. **Challenges faced** during the lab and how they were overcome.

**Report Template**:
- Title Page
- Table of Contents
- Introduction to YARA
- YARA Rules Created (with explanation and screenshots)
- Test Results
- Challenges and Learnings
- Conclusion

---

### **Final Submission**:
Submit your report as a **PDF file** to the instructor by the end of the lab session.

---
