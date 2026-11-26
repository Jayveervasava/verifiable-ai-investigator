# vai/web - Web UI + Demo (Claude 5)

## Chalane ka tarika (5 minute demo, offline)
```
pip install -r vai/web/requirements-web.txt
export DEMO_PASSWORD=demo123          # Windows: set DEMO_PASSWORD=demo123
uvicorn vai.web.app:app --port 8000
```
Browser mein http://127.0.0.1:8000 kholo. DEMO_PASSWORD set nahi hai to login band rehta hai (sirf local demo ke liye).

## Demo flow
1. Cases -> FIR-1427/2027 kholo -> **Run investigation** (steps ledger mein live aate hain).
2. **Verify chain** + **Check completeness** (dono green).
3. Tamper: "edit a step" -> Simulate tampering -> Verify chain (red, step 3). **Restore original**.
4. Tamper: "delete a step" step 7 -> Verify chain green, **Check completeness** red (yehi completeness ka point hai).
5. **Ask AI why**, **Approve**, **Download report**, **Section 63 draft**, **Export evidence package**.

## Environment variables
DEMO_PASSWORD, VAI_RESULTS_DIR (default results/web), VAI_STEP_DELAY (default 0.7 sec), VAI_MAX_UPLOAD_MB (20), VAI_FORCE_MOCK=1, LLM_API_KEY (agent ke liye, optional).

## Real packages vs mocks
Har package (evidence, ledger, agent, legal) alag se try-import hota hai; na mile to mock use hota hai. Case page / Settings JSON mein `view.backends` dikhata hai kaun sa real/mock hai.
Tamper demo hamesha ledger ki COPY par chalta hai; asli ledger kabhi nahi badalta. Re-run purani ledger archive folder mein rakhta hai, delete nahi karta.
