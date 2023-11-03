Authorizations that should not be allowed:
    Roles strictly included in other Authorization Role, for the same UserGroup, for the same scope (resource).

Are implicit Authorizations based on just the user and/or his membership a good thing? What would use-cases be?
    Let's say a user creates an issue. He should be able to edit it, close it, but not moderate it further.
    Similar case for an issue's comments.

    So do you give the user Authorizations at Issue creation time, or just based on who the issue's author is?
    In this case if the user leaves the org, you want the issue to remain, as well as who created it.

    What about assignees? Should a restriction to only allow assignees that have access to the issue be put in place in the first place?
    What if the assignee is later removed from the users with permissions?
