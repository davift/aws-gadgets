# aws-gadgets

This is my ground dump for my gadgets to speed up troubleshooting on AWS.

## Gadgets

- `activity.py`
  - This script collects activities for a specific AIM User for granter and denied permissions.
  - The value of this information is to appropriately grant only the bare minimum permissions and revoke the unnecessary ones.
    - Dependencies: `boto3` (required) and `tabulate` (optional with easy code changes)
    - To analyze roles' activities, change the flag inside the code.

Usage:

```
activity.py <username/role_arn> <hours>
```

Example:

```
activity.py AppUser 3
```

Output:

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_01.png)

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_02.png)

![Output_No_Events](https://github.com/davift/aws-gadgets/blob/main/output_03.png)


