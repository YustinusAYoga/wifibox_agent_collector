@app.post("/upload")
async def upload_file(request: Request):
    """Handle upload via query parameters, avoiding Pydantic/Cython signature inspection bugs"""
    client_ip = request.client.host if request.client else "Unknown IP"
    
    # Manually pull query parameters from the request
    uid = request.query_params.get("uid")
    ip = request.query_params.get("ip")
    
    if not uid or not ip:
        logger.warning(f"[{client_ip}] Missing 'uid' or 'ip' query parameters.")
        raise HTTPException(status_code=400, detail="Missing 'uid' or 'ip' query parameters.")
    
    logger.info(f"[{client_ip}] Incoming upload request - UID: '{uid}', IP: '{ip}'")
    
    try:
        safe_uid = os.path.basename(str(uid))
        safe_ip = str(ip).strip()

        # Define the target directory and file path
        target_dir = os.path.join(UPLOAD_DIR, safe_uid)
        
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"[{client_ip}] Failed to create directory '{target_dir}': {e}")
            raise HTTPException(status_code=500, detail=f"Server Folder Error: {str(e)}")

        filepath = os.path.join(target_dir, "wifibox_identification.json")

        # Construct the requested JSON content
        identification_data = [
            {
                "uid": safe_uid,
                "wg_ip": safe_ip
            }
        ]

        # Write the JSON data to the file
        with open(filepath, 'w') as f:
            json.dump(identification_data, f, indent=2)
        
        logger.info(f"[{client_ip}] Successfully created wifibox_identification.json for UID '{safe_uid}'")

        # Automatically update the master inventory file
        update_inventory_file(filepath)

        return {
            "status": "success",
            "message": f"Identification file created and inventory updated for UID {safe_uid}."
        }
        
    except HTTPException:
        raise 
    except Exception as e:
        logger.error(f"[{client_ip}] Unexpected error during upload for UID '{uid}': {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected Internal Server Error: {str(e)}")
