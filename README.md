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

For what it can not do, check the [shortcomings](#shortcomings).


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

Now we might want to ensure that only members/collaborators of the same organization that owns the issue may receive authorization. For that we must establish the owner_relation (field) of the Issue model, and set up an implicit condition that will represent our Membership check.
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
- `Conditions` are usually evaluated by their `resources_q` method, which returns a Django `Q` that matches the resources (filtering out the ones the actor is not authorized for). 
  - They may optionally implement an `assigned_perms_q` method to prefetch any AssignedPerms from the database that might be used in the `resources_q` method.
  - In the current version, there is also an `is_authorized_for_unsaved_resource` method, that is used for as you might have guessed, resources that have not yet been saved to the database.


## Performance

- Although proper benchmarks haven't been conducted, performance should be decent. Most authorization checks can be done with 2 queries: one to fetch AssignedPerms, and one to filter the resources which the user is authorized to act on.


## Current status and future plans

- Although the library hasn't reached version 1.0 yet, it is soon going to be used in production at Presslabs, with most, if not all of it's functionality tested.
- This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). That means until version 1.0, breaking changes are to be expected from one version to another, although they will be documented in the [changelog](CHANGELOG.MD).
- There is a good chance for pre-1.0 versions to be maintained for a while, in terms of compatibility with newer Django and Python versions, as well as critical bugfixes. You might have to provide a pull request yourself though, but we'll, at the least, review it and hopefully ship it in a maintenance release.
- The abstractions around how Conditions are composed and relate to AuthorizationSchemes/Solver could've been more inspired (see [Shortcomings and Limitations](#shortcomings-and-limitations)). Therefore, a major rework could happen before the 1.0 release, but chances are it will take a while longer to materialize, as the current API is *usable* enough.


## Shortcomings and Limitations

- The models and logic currently work with a single owner type relation, pointing to the Django `AUTH_USER_MODEL`. This implies that your Organizations must share the same model with your Users (which we believe simplifies things for most cases). It should be possible to work around this limitation, but out of the box everything is set up to work this way.
- It's hard (and not performant) to interrogate who all the users with privileges for a resource are.
- It's not possible to define and store new permissions/roles in the DB.
- It's cumbersome to verify if a subset of *Conditions* is being met. And when enforcing authorization, it's kind of impossible to reveal the conditions that have not been met.
- Verifying authorization for already prefetched resources, in cases where conditions can be satisfied without the need to fetch AssignedPerms, or the AssignedPerms have been prefetched as well, could be more performant. The best way of doing it now is filtering which of them the actor is authorized for, as if they weren't prefetched to begin with.
- For some cases, prefetching AssignedPerms could be avoided, and the whole authorization interrogation could be done with a single query... but not with how the abstraction is currently built. That single query would consist of more DB joins, so it's hard to tell if a potential performance increase is left on the table or not, without actual benchmarks.
- Memberships could be made more optional in the whole design, but it's not clear if that's of any importance right now.
- Some "meta" indirect privileges are hard (or even impossible) to implement, especially in a performant manner. For example: giving privileges that other users possess, based on a relation between the actor and the respective users, if say they are part of the same UserGroups. 
- This library is mostly intended to be used in conjunction with APIs. There is (currently) no built-in support for the Django Admin, and no plan to add one unless there is enough interest for it and somebody contributes it. 
- Authorization Schemes are based on Python classes, and not on some configuration system, but this is more of a preference thing.

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
