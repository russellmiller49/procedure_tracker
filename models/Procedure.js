// models/Procedure.js - Medical procedure tracking model
module.exports = (sequelize, DataTypes) => {
  const Procedure = sequelize.define('Procedure', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    procedure_type: {
      type: DataTypes.STRING,
      allowNull: false
    },
    procedure_date: {
      type: DataTypes.DATE,
      allowNull: false
    },
    patient_identifier: {
      type: DataTypes.STRING,
      allowNull: false
    },
    performer_id: {
      type: DataTypes.UUID,
      allowNull: false
    }
  }, {
    tableName: 'procedures',
    timestamps: true,
    underscored: true,
    paranoid: true
  });

  Procedure.associate = models => {
    Procedure.belongsTo(models.User, { foreignKey: 'performer_id', as: 'performer' });
  };

  return Procedure;
};
