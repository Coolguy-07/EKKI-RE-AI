rule Demo_Benign_Rule : Test
{
    meta:
        description = "Benign demonstration rule for baseline testing"
        author = "EKKI-RE-AI"
        severity = "info"
        version = "1.0"
    
    strings:
        $s1 = "This is a benign string used for testing YARA engine integration." ascii
    
    condition:
        $s1
}
