"""add description column to TaskTypes

Revision ID: f4ef38f8da9a
Revises: 
Create Date: 2025-04-19 18:00:20.346708

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f4ef38f8da9a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('TaskTypes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('description', sa.String(length=300), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('TaskTypes', schema=None) as batch_op:
        batch_op.drop_column('description')

    # ### end Alembic commands ###
