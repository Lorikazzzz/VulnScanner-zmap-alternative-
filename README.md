# An powerfull alternative to ZMap

**This project is still under development so it will improve overtime** \
Also feel free to suggest things!
## Tests

4 scan threads on a 4 core vps: \
![4 scan threads](https://github.com/user-attachments/assets/11573427-4423-43b2-add3-8109786c5dcf)

20 Scan threads on millanox connect-X 3 dedi: \
![1 Scan thread](https://github.com/user-attachments/assets/b0c7eaf2-9162-432d-a7bb-331f8224d48e)

Commands: \
![Commands](https://github.com/user-attachments/assets/a5fb779b-7b42-4899-90ab-37655d6b4041)

**Note: These tests are made WITHOUT pfring support**

## Compilation

```bash
git clone https://github.com/Lorikazzzz/VulnScanner-zmap-alternative-.git
cd VulnScanner-zmap-alternative-
make (Add USE_PFRING_ZC=1 for pfring support)
```

  
## Sources

[Zmap](https://github.com/zmap/zmap) \
[Masscan](https://github.com/robertdavidgraham/masscan) \
[PFRING](https://github.com/ntop/PF_RING)



  
