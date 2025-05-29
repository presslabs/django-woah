# django-woah
A package intended to aid developers in implementing authorization for Django apps.  

*This project is developed at [Presslabs](https://www.presslabs.com/).*

## Installation
`pip install django-woah`

Then, in your `settings.py`, add it to the `INSTALLED_APPS`:
```python
INSTALLED_APPS = [
    # [...]
    "django_woah",
]
```


## What it can do

- It can handle Organizations, Teams (including nesting sub-teams to some degree) and Memberships (including outside collaborators)
- It can handle per user, as well as Organization-wide and Team-wide privileges
- It can handle per object, as well as per model permissions
- It can filter the resources for which a (single) actor is authorized (most of the time, with 2 DB queries), based on the defined AuthorizationSchemes, given a set of permissions to check
- It offers some built-in support for Django REST Framework (DRF).
- Authorization Schemes are based on Python classes. They don't strictly follow pre-existing authorization patterns, such as ABAC or (P)RBAC, but they could be used to achieve similar functionality.

For what it can not do, check the [shortcomings and limitations](#shortcomings-and-limitations).


## How it looks

Let's say we're making an issue tracker kind of app. Then, our Issue model might look something like this:
```python
# my_app/issue_tracker/models.py
class Issue(models.Model):
    owner = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="owned_issues"
    )
    author = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="authored_issues",
    )
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="issues"
    )
    title = models.CharField(max_length=512)
    content = models.TextField()
    state = models.CharField(max_length=16, default=IssueState.OPEN)
```

Now, let's define an AuthorizationScheme for our Issue model, starting with some CRUD permissions, and a permission for closing/reopening issues. We'll also add an Issue Manager role:

```python
# my_app/issue_tracker/authorization.py
# Here you can define authorization schemes for your models

from django_woah.authorization import ModelAuthorizationScheme, PermEnum

class IssueAuthorizationScheme(ModelAuthorizationScheme):
    model = Issue

    class Perms(PermEnum):
        # The values here are up to preference. But we're going
        # to use an "issue:" prefix, to avoid collisions with other
        # model perms and roles, when storing to the database.
        ISSUE_VIEW = "issue:issue_view"
        ISSUE_CREATE = "issue:issue_create"
        ISSUE_EDIT_CONTENT = "issue:issue_edit_content"
        ISSUE_CHANGE_STATE = "issue:issue_change_state"
        ISSUE_DELETE = "issue:issue_delete"

    class Roles(PermEnum):
        ISSUE_MANAGER = "issue:manager"
```

We want our Issue Manager role to receive all the permissions above, so we are going to add some indirect permissions logic to our IssueAuthorizationScheme:
```python
# my_app/issue_tracker/authorization.py
from django_woah.authorization import (
    # [...]
    IndirectPerms, ConditionalPerms, HasSameResourcePerms,
)

class IssueAuthorizationScheme(ModelAuthorizationScheme):
    # [...]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    HasSameResourcePerms([self.Roles.ISSUE_MANAGER]),
                ],
                receives_perms=self.Perms.values(),
            ),
        ]
```

Now we might want to ensure that only members/collaborators of the organization that owns the issue may receive authorization. For that we must establish the owner_relation (field) of the Issue model, and set up an implicit condition that will represent our Membership check.
```python
# my_app/issue_tracker/authorization.py

class IssueAuthorizationScheme(ModelAuthorizationScheme):
    # [...]
    owner_relation = "owner"  # this references the owner ForeignKey field in our Issue model 

    def get_implicit_conditions(
        self, context: Context
    ) -> list[Condition]:
        return [
            HasRootMembership(actor=context.actor),
        ]
    
    # [...]
```

Noticed the `project` field in the `Issue` model? It can be used to organize a bunch of issues. Let's then allow assigning permissions in a project-wide manner. To achieve this, we need to add another indirect way of obtaining permissions for Issues:

```python
# my_app/issue_tracker/authorization.py
from django_woah.authorization import TransitiveFromRelationPerms


class IssueAuthorizationScheme(ModelAuthorizationScheme):
    # [...]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            # [...],
            # You'd need to have a ProjectAuthorizationScheme in place for
            # this to properly work, but it's out of scope for this example.
            TransitiveFromRelationPerms(
                relation="project",
            ),
        ]
```

What if we want to allow authors to manage their own issues a bit?
```python
from django_woah.authorization import QCondition
# [...]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            # [...],
            ConditionalPerms(
                conditions=[
                    # The implicit membership condition we defined above,
                    # will still apply, so if the author were to lose
                    # membership, this condition will not apply anymore.
                    QCondition(Q(author=context.actor)),
                ],
                receives_perms=[
                  self.Perms.ISSUE_VIEW,
                  self.Perms.ISSUE_EDIT_CONTENT,
                  self.Perms.ISSUE_CHANGE_STATE,
                ],
            ),
        ]
```
To see more code in action you can check the [examples](https://github.com/presslabs/django-woah/tree/master/examples), or read about [how it all works](#how-it-all-works).


## How it all works

### Django models
- `UserGroups` represents, as the name implies, a group of users; for convenience these can be used to represent a single user, a Team, or the entirety of members/collaborators of an organization/account.
- `Memberships` are used to represent a Django User's membership into the aforementioned UserGroups.
- `AssignedPerms` represent the direct relation between a `UserGroup` (actors), a `Perm`/`Role` and a `resource` (usually a Django Model instance or class).
### Authorization classes
- `AuthorizationSchemes` define what actors are allowed to do, and under what `Conditions`.
  - They contain `Permissions` definitions; `Roles` can be defined separately, but they are permissions too.
  - Users can dynamically be given additional Perms based on Conditions.
  - Additionally, implicit Conditions may be applied at the AuthorizationScheme level, including to the already directly AssignedPerms.
- An `AuthorizationSolver` glues together the user-defined AuthorizationSchemes. It's responsible for enforcing authorization.
- A `Context` consists mostly of an actor, permissions and a resource, and an optional `extra` field. It acts both as a query and state, and it's passed to the AuthorizationSolver.
- `Conditions` are what authorization is granted (or not) on.
  - Each condition usually implements two important methods:
    - the `get_resources_q` method, which returns a Django `Q` that filters the resources that match the condition, and is the one used when fetching resources from the DB;
    - the `verify_authorization` method (name is subject to change), which returns a `bool`, and is used to verify the condition for prefetched or about to be created resources.
  - Optionally, but more usual than not, there are two other methods which may be implemented:
      - the `get_assigned_perms_q` method, which is used to prefetch any `AssignedPerms` from the database, that might be of use in the previously mentioned important methods;
      - the `get_memberships_q` method, which is used to prefetch any `Memberships` from the database; although it may be used in `get_resources_q`, it's more commonly used in the `verify_authorization` methods that belong to conditions related to memberships. 


## Performance

- Although proper benchmarks haven't been conducted, performance should be decent:
  - Most resources authorization checks can be done with 2 queries: one to fetch AssignedPerms, and one to filter the resources on which the actor is authorized to perform, assuming the actor is prefetched and doesn't count.
  - Fetching what actors are authorized on a resource require at least 3 queries: one to fetch AssignedPerms, Memberships and finally the Actor(s).

## Current status and future plans

- The library has been used in production at Presslabs since ~2024.04 (v0.1.3), with most (if not all) of its functionality tested in an _external_ project, which runs and is monitored in production, and is backed up by hundreds of automated CI tests that engage the authorization logic.
- This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). That means until version 1.0, breaking changes are to be expected from one version to another, although they will be documented in the [changelog](CHANGELOG.MD).
- There is a good chance for pre-1.0 versions to be maintained for a while, in terms of compatibility with newer Django and Python versions, as well as critical bugfixes. You might have to provide a pull request yourself though, but we'll, at the least, review it and hopefully ship it in a maintenance release.
- The abstractions around how Conditions are composed and relate to AuthorizationSchemes/Solver could've been more inspired (see [Shortcomings and Limitations](#shortcomings-and-limitations)). Therefore, a major rework could happen before the 1.0 release, but chances are it might only materialize after that release, as the current API is *usable* enough.
- Some Docs would be nice.
- More examples and in-project testing would be nice too.


## Shortcomings and Limitations

### Important ones
- The models and logic currently work with a single owner type relation, pointing to the Django `AUTH_USER_MODEL`. This implies that your Organizations must share the same model with your Users (which we believe simplifies things for most cases). `Account` could be your model name to represent both Users and Organizations. While it should be possible to work around this assumption, everything is set up to work this way out of the box.
- It's not trivial to define and store new permissions/roles in the DB, at least there's no out of the box support for it.

### Minor ones
- While this library handles most authorization rules you can practically expect to use, it probably won't handle every imaginable or weird case.
- There is (currently) no planned support for the Django Admin.
- Memberships could be made more optional in the whole design, but it's not clear if that's of any importance right now.
- Authorization Schemes are based on Python classes, and their serialization is of no priority. 

If these are dealbreakers for you or you are simply looking for something else, check the [alternatives](#alternatives).


## Contributing

- For security related issues (think exploitable bugs), contact us at `ping@presslabs.com`.
- For other type of bugs, use the [issue tracker](https://github.com/presslabs/django-woah/issues).
- If you have questions, or want to talk about missing functionality, open a [discussion](https://github.com/presslabs/django-woah/discussions).
- You may send a [pull request](https://github.com/presslabs/django-woah/pulls) for bugfixing, if you think you've got it right. For anything else, if the implementation details have not already been decided, it's better to start a [discussion](https://github.com/presslabs/django-woah/discussions) first.   
  Do take note that we're looking to implement a CLA for code contributions.
- For anything else, just use common sense and it will probably be fine.


## Alternatives

- https://github.com/pycasbin/django-authorization
- https://github.com/dimagi/django-prbac
- https://github.com/osohq/oso/tree/main/languages/python/django-oso/ (deprecated, but not EoL-ed for now)
