# aws-gadgets

This is my ground dump for my gadgets to speed up troubleshooting on AWS.

## Gadgets

- `activity.py`
  - This script collects activities for a specific AIM User / Role for granter and denied permissions.
  - The value of this information is to appropriately grant only the bare minimum permissions and revoke the unnecessary ones.
    - Dependencies: `boto3` (required), `re` (required), and `tabulate` (optional with easy code changes)

Usage:

```
python3 activity.py <username/role_arn> <hours>
```

Example:

```
python3 activity.py AppUser 3
```

```
python3 activity.py arn:aws:iam::accountId:role/roleName 24
```

Output:

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_01.png)

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_02.png)

Show related ARNs or hit Ender to exit:

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_03.png)

## Notes

Feel free to report bugs, suggest features, and contribute to the code.
