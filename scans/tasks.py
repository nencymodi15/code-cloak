import time
import hashlib
from celery import shared_task
from .models import Scan, FileSignature

@shared_task
def run_security_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = Scan.Status.RUNNING
        scan.save()

        time.sleep(3) # Simulate deep scan time

        sha256_hash = ""
        file_size = 0
        header_hex = ""

        if scan.file:
            file_path = scan.file.path
            sha256_merkle = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                header_bytes = f.read(32)
                header_hex = header_bytes.hex().upper()
                
                f.seek(0)
                while chunk := f.read(8192):
                    sha256_merkle.update(chunk)
                    file_size += len(chunk)
            
            sha256_hash = sha256_merkle.hexdigest()
        else:
            fake_bytes = scan.file_name.encode('utf-8')
            sha256_hash = hashlib.sha256(fake_bytes).hexdigest()
            file_size = len(fake_bytes)
            header_hex = fake_bytes[:16].hex().upper()

        print(f"\n[DEBUG] File Name: {scan.file_name}")
        print(f"[DEBUG] Read Header Hex: {header_hex}")

        risk_score = 5
        detected_category = "unknown"
        matched_signature = None

        # 1. Database-driven Magic Byte Inspection
        if scan.file:
            signatures = FileSignature.objects.all()
            print(f"[DEBUG] Found {signatures.count()} signatures in database.")
            for sig in signatures:
                sig_hex = (sig.magic_bytes_hex or "").replace(" ", "").upper()
                print(f"[DEBUG] Checking against DB Sig -> Ext: {sig.extension}, Hex: {sig_hex}")
                
                if sig_hex and header_hex.startswith(sig_hex):
                    matched_signature = sig
                    risk_score = sig.default_risk_score
                    detected_category = sig.file_category.lower()
                    print(f"[DEBUG] MATCH FOUND! Category: {detected_category}, Base Risk: {risk_score}")
                    break

        # 2. Filename keyword heuristic check
        name_lower = (scan.file_name or "").lower()
        is_suspicious_name = any(kw in name_lower for kw in ['malware', 'trojan', 'payload', 'exploit'])
        if is_suspicious_name:
            risk_score = max(risk_score, 90)
            print(f"[DEBUG] Suspicious name triggered! Risk score: {risk_score}")

       # 3. Extension Spoofing Detection
        if scan.file and matched_signature:
            user_ext = scan.file_name.split('.')[-1].lower() if '.' in scan.file_name else ""
            expected_ext = matched_signature.extension.lower()
            
            # If the file extension doesn't match what the binary headers actually are, flag it!
            if user_ext != expected_ext:
                risk_score = 99

        # Update record with true metrics
        scan.sha256_hash = sha256_hash
        scan.file_size = file_size
        scan.risk_score = risk_score
        scan.status = Scan.Status.COMPLETED
        scan.save()

        return f"Scan {scan_id} successfully processed. Risk Score: {risk_score}"

    except Scan.DoesNotExist:
        return f"Scan {scan_id} not found."
    except Exception as e:
        scan.status = Scan.Status.FAILED
        scan.save()
        raise e