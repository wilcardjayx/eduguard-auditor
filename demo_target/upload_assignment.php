<?php
// VULN: Unrestricted file upload without extension or MIME check (EDU-PRIV-001)
if (isset($_FILES['assignment'])) {
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($_FILES["assignment"]["name"]);
    move_uploaded_file($_FILES["assignment"]["tmp_name"], $target_file);
    echo "Assignment uploaded successfully.";
}
?>
